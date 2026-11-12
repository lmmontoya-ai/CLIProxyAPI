package auth

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

// QuotaRecoveryChecker confirms that a credential in quota cooldown has room
// again. It must honor ctx and return false when recovery cannot be confirmed.
type QuotaRecoveryChecker interface {
	QuotaRecovered(ctx context.Context, auth *Auth, models []string) bool
}

const (
	quotaRecoveryInterval      = time.Minute
	quotaRecoveryTimeout       = 3 * time.Second
	quotaRecoveryMaxConcurrent = 3
	quotaRecoveryMaxEntries    = 256
	// Leave short retry windows and transient overload/rate backoffs alone.
	quotaRecoveryMinRemaining = 30 * time.Second
)

type quotaRecoveryCall struct {
	ready     chan struct{}
	expires   time.Time
	recovered bool
}

type quotaRecoveryState struct {
	mu     sync.Mutex
	calls  map[string]*quotaRecoveryCall
	active int
}

// recoverQuotaBeforeReject is only reached after selection fails. Normal
// requests and idle hubs do no usage I/O. Selection is retried at most once.
func (m *Manager) recoverQuotaBeforeReject(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, err error) bool {
	if m == nil || err == nil || ctx.Err() != nil || m.HomeEnabled() || m.hasPluginScheduler() {
		return false
	}
	var cooldownErr *modelCooldownError
	if !errors.As(err, &cooldownErr) {
		return false
	}
	providerSet := make(map[string]bool, len(providers))
	for _, provider := range providers {
		providerSet[canonicalSchedulingProvider(provider)] = true
	}
	pinned := pinnedAuthIDFromMetadata(opts.Metadata)
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	reg := registry.GetGlobalRegistry()
	candidates := make([]*Auth, 0)
	for _, auth := range m.List() {
		if auth == nil || !providerSet[canonicalSchedulingProvider(executorKeyFromAuth(auth))] ||
			(pinned != "" && auth.ID != pinned) || !eligibility.allows(auth) {
			continue
		}
		if _, used := tried[auth.ID]; used {
			continue
		}
		if !m.authSupportsRouteModel(reg, auth, model) {
			continue
		}
		// Resolve aliases before inspecting which model the request would use.
		checkModel := m.selectionModelForAuth(auth, model)
		if !hasLiveQuotaCooldown(auth, checkModel, time.Now()) {
			continue
		}
		candidates = append(candidates, auth)
	}
	return len(m.recoverQuotaCandidates(ctx, candidates)) > 0
}

// RecoverQuotaCooldowns performs an explicit, bounded recovery pass. There is
// no periodic usage polling; ordinary recovery is triggered by failed selection.
func (m *Manager) RecoverQuotaCooldowns(ctx context.Context) []string {
	if m == nil || m.HomeEnabled() {
		return nil
	}
	return m.recoverQuotaCandidates(ctx, m.List())
}

func (m *Manager) recoverQuotaCandidates(ctx context.Context, candidates []*Auth) []string {
	if ctx.Err() != nil {
		return nil
	}
	// Stable ordering makes concurrent requests join the same checks. Throttled
	// entries are skipped so later requests can progress through larger pools.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i] == nil {
			return false
		}
		return candidates[j] == nil || candidates[i].ID < candidates[j].ID
	})
	type pendingCheck struct {
		id   string
		call *quotaRecoveryCall
	}
	pending := make([]pendingCheck, 0, quotaRecoveryMaxConcurrent)
	for _, auth := range candidates {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled || hasUnauthorizedAuthFailure(auth) {
			continue
		}
		models, ok := longQuotaCooldownModels(auth, time.Now())
		if !ok {
			continue
		}
		executor, _ := m.Executor(executorKeyFromAuth(auth))
		checker, ok := executor.(QuotaRecoveryChecker)
		if !ok {
			continue
		}
		if call := m.startQuotaRecovery(ctx, auth, models, checker); call != nil {
			pending = append(pending, pendingCheck{auth.ID, call})
		}
		if len(pending) == quotaRecoveryMaxConcurrent {
			break
		}
	}
	if len(pending) == 0 {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, quotaRecoveryTimeout)
	defer cancel()
	completed := make(chan pendingCheck, len(pending))
	for _, pending := range pending {
		go func() {
			select {
			case <-pending.call.ready:
				completed <- pending
			case <-waitCtx.Done():
			}
		}()
	}
	for range pending {
		select {
		case pending := <-completed:
			if pending.call.recovered {
				return []string{pending.id}
			}
		case <-waitCtx.Done():
			return nil
		}
	}
	return nil
}

func (m *Manager) startQuotaRecovery(ctx context.Context, auth *Auth, models []string, checker QuotaRecoveryChecker) *quotaRecoveryCall {
	state := &m.quotaRecovery
	now := time.Now()
	state.mu.Lock()
	defer state.mu.Unlock()
	if call := state.calls[auth.ID]; call != nil {
		select {
		case <-call.ready:
			if now.Before(call.expires) {
				return nil
			}
		default:
			return call
		}
	}
	if state.calls == nil {
		state.calls = make(map[string]*quotaRecoveryCall)
	}
	for id, call := range state.calls {
		select {
		case <-call.ready:
			if !now.Before(call.expires) {
				delete(state.calls, id)
			}
		default:
		}
	}
	if state.active >= quotaRecoveryMaxConcurrent || len(state.calls) >= quotaRecoveryMaxEntries {
		return nil
	}
	call := &quotaRecoveryCall{ready: make(chan struct{})}
	state.calls[auth.ID] = call
	state.active++
	go func() {
		// A canceled waiter must not cancel a lookup shared by other requests.
		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), quotaRecoveryTimeout)
		defer cancel()
		recovered := false
		if checker.QuotaRecovered(checkCtx, auth, models) && checkCtx.Err() == nil {
			updated, _, errReset := m.resetQuota(checkCtx, auth.ID, auth)
			if errReset != nil {
				log.Warnf("quota recovery failed: auth=%s error=%v", auth.ID, errReset)
			} else if updated != nil {
				recovered = true
				log.Infof("cleared quota cooldown after usage check: auth=%s models=%v", auth.ID, models)
			}
		}
		state.mu.Lock()
		call.recovered = recovered
		call.expires = time.Now().Add(quotaRecoveryInterval)
		state.active--
		close(call.ready)
		state.mu.Unlock()
	}()
	return call
}

// A whole-credential reset requires confirmed room for every blocked model.
// Never erase transient rate/overload backoff, authentication or other errors.
func longQuotaCooldownModels(auth *Auth, now time.Time) (models []string, ok bool) {
	if auth == nil {
		return nil, false
	}
	// The public snapshot only shows the effective outer quota deadline. A
	// shorter independent restriction can still be live underneath that layer,
	// and a whole-credential reset would erase it too.
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		if state.Status == StatusDisabled {
			return nil, false
		}
		shadow := state.credentialQuotaShadow
		if shadow == nil {
			continue
		}
		if shadow.Status == StatusDisabled {
			return nil, false
		}
		blocked, _, next := availabilityBlock(shadow.Unavailable, shadow.Quota.Exceeded, shadow.NextRetryAfter, shadow.Quota.NextRecoverAt, now)
		if !blocked {
			continue
		}
		view := newCooldownView("model", "", next, now, shadow.Quota, shadow.StatusMessage, shadow.LastError)
		if view.Reason != "quota" && view.Reason != "credential_quota" {
			return nil, false
		}
	}
	long := false
	for _, view := range CooldownSnapshotForAuth(auth, now) {
		switch view.Reason {
		case "quota", "credential_quota":
			if view.RetryAt.Sub(now) > quotaRecoveryMinRemaining {
				long = true
			}
			if view.ModelKey != "" {
				models = append(models, view.ModelKey)
			}
		default:
			return nil, false
		}
	}
	return models, long
}
