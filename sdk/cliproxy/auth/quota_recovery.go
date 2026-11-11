package auth

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// QuotaRecoveryChecker is implemented by executors that can confirm, outside
// the request path, that a credential in a long quota cooldown has room again.
// It must return false whenever recovery cannot be confirmed.
type QuotaRecoveryChecker interface {
	QuotaRecovered(ctx context.Context, auth *Auth, models []string) bool
}

const (
	quotaRecoveryInitialDelay = 30 * time.Second
	quotaRecoveryInterval     = 10 * time.Minute
	// quotaRecoveryMinRemaining skips cooldowns that will expire soon anyway.
	quotaRecoveryMinRemaining = 10 * time.Minute
)

func (m *Manager) runQuotaRecoveryLoop(ctx context.Context) {
	timer := time.NewTimer(quotaRecoveryInitialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		m.RecoverQuotaCooldowns(ctx)
		timer.Reset(quotaRecoveryInterval)
	}
}

// RecoverQuotaCooldowns lifts long quota cooldowns that the credential's
// executor confirms have recovered early, and returns the reset auth IDs.
func (m *Manager) RecoverQuotaCooldowns(ctx context.Context) []string {
	if m == nil || m.HomeEnabled() {
		return nil
	}
	var reset []string
	for _, auth := range m.List() {
		if ctx.Err() != nil {
			return reset
		}
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		models, ok := longQuotaCooldownModels(auth, time.Now())
		if !ok {
			continue
		}
		executor, okExecutor := m.Executor(auth.Provider)
		if !okExecutor {
			continue
		}
		checker, okChecker := executor.(QuotaRecoveryChecker)
		if !okChecker || !checker.QuotaRecovered(ctx, auth, models) {
			continue
		}
		if _, _, errReset := m.ResetQuota(ctx, auth.ID); errReset != nil {
			log.WithError(errReset).WithField("auth", auth.ID).Warn("failed to clear recovered quota cooldown")
			continue
		}
		log.WithFields(log.Fields{"auth": auth.ID, "models": models}).Info("cleared quota cooldown: live usage shows the credential has room")
		reset = append(reset, auth.ID)
	}
	return reset
}

// longQuotaCooldownModels returns the models under quota cooldown on auth when
// at least one quota cooldown outlasts quotaRecoveryMinRemaining. ok is false
// when there is no such cooldown, or when the auth also carries a restriction
// that is not about quota, since ResetQuota would clear that too.
func longQuotaCooldownModels(auth *Auth, now time.Time) (models []string, ok bool) {
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
		case "transient_error", "transient_rate_limit":
		default:
			return nil, false
		}
	}
	return models, long
}
