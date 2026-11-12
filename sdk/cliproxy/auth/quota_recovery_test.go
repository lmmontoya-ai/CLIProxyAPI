package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

type quotaRecoveryExecutor struct {
	successExecutor
	recovered bool
	checks    atomic.Int32
	models    []string
	check     func(context.Context, *Auth, []string) bool
}

func (e *quotaRecoveryExecutor) QuotaRecovered(ctx context.Context, auth *Auth, models []string) bool {
	e.checks.Add(1)
	if e.check != nil {
		return e.check(ctx, auth, models)
	}
	e.models = append([]string(nil), models...)
	return e.recovered
}

func newQuotaRecoveryManager(t *testing.T, executor ProviderExecutor) (*Manager, *Auth) {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &Auth{ID: uuid.NewString() + "-claude-recovery", Provider: "claude", Attributes: map[string]string{"api_key": "test-key"}}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: "claude-fable-5-2"}, {ID: "claude-opus-5-5"}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	return manager, auth
}

func markClaudeQuota(manager *Manager, authID, model string, retryAfter time.Duration, credentialScope bool) {
	manager.MarkResult(context.Background(), Result{
		AuthID:          authID,
		Provider:        "claude",
		Model:           model,
		RetryAfter:      &retryAfter,
		CredentialScope: credentialScope,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "rate limit"},
	})
}

func TestRecoverQuotaCooldownsClearsConfirmedCredentialLockout(t *testing.T) {
	executor := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	manager, auth := newQuotaRecoveryManager(t, executor)
	markClaudeQuota(manager, auth.ID, "claude-fable-5-2", 75*time.Hour, true)

	reset := manager.RecoverQuotaCooldowns(context.Background())
	if len(reset) != 1 || reset[0] != auth.ID {
		t.Fatalf("reset = %v, want [%s]", reset, auth.ID)
	}
	if len(executor.models) == 0 || executor.models[0] != "claude-fable-5-2" {
		t.Fatalf("checked models = %v, want the cooled model", executor.models)
	}
	updated, _ := manager.GetByID(auth.ID)
	if views := CooldownSnapshotForAuth(updated, time.Now()); len(views) != 0 {
		t.Fatalf("cooldowns after recovery = %+v, want none", views)
	}
}

func TestRecoverQuotaCooldownsKeepsUnconfirmedLockout(t *testing.T) {
	executor := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: false}
	manager, auth := newQuotaRecoveryManager(t, executor)
	markClaudeQuota(manager, auth.ID, "claude-fable-5-2", 75*time.Hour, true)

	if reset := manager.RecoverQuotaCooldowns(context.Background()); len(reset) != 0 {
		t.Fatalf("reset = %v, want none", reset)
	}
	updated, _ := manager.GetByID(auth.ID)
	if views := CooldownSnapshotForAuth(updated, time.Now()); len(views) == 0 {
		t.Fatal("lockout was cleared although recovery was not confirmed")
	}
}

func TestRecoverQuotaCooldownsSkipsShortCooldownsAndUnsupportedExecutors(t *testing.T) {
	executor := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	manager, auth := newQuotaRecoveryManager(t, executor)
	markClaudeQuota(manager, auth.ID, "claude-opus-5-5", 20*time.Second, false)
	if reset := manager.RecoverQuotaCooldowns(context.Background()); len(reset) != 0 || executor.checks.Load() != 0 {
		t.Fatalf("short cooldown: reset=%v checks=%d, want no check", reset, executor.checks.Load())
	}

	plain, plainAuth := newQuotaRecoveryManager(t, &successExecutor{provider: "claude"})
	markClaudeQuota(plain, plainAuth.ID, "claude-fable-5-2", 75*time.Hour, true)
	if reset := plain.RecoverQuotaCooldowns(context.Background()); len(reset) != 0 {
		t.Fatalf("executor without checker: reset = %v, want none", reset)
	}
}

func TestRecoverQuotaCooldownsSkipsNonQuotaRestrictions(t *testing.T) {
	executor := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	manager, auth := newQuotaRecoveryManager(t, executor)
	markClaudeQuota(manager, auth.ID, "claude-fable-5-2", 75*time.Hour, false)
	manager.MarkResult(context.Background(), Result{
		AuthID:   auth.ID,
		Provider: "claude",
		Model:    "claude-opus-5-5",
		Error:    &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"},
	})
	if reset := manager.RecoverQuotaCooldowns(context.Background()); len(reset) != 0 || executor.checks.Load() != 0 {
		t.Fatalf("reset=%v checks=%d, want the auth left alone", reset, executor.checks.Load())
	}
}

func TestQuotaRecoveryRetriesSelectionForCurrentRequest(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, mixed := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/mixed=%v", legacy, mixed), func(t *testing.T) {
				e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
				m, a := newQuotaRecoveryManager(t, e)
				if legacy {
					s := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RoundRobinSelector{}})
					m.SetSelector(s)
					t.Cleanup(s.Stop)
				}
				markClaudeQuota(m, a.ID, "claude-opus-5-5", 2*time.Hour, true)
				var selected *Auth
				var err error
				if mixed {
					selected, _, _, err = m.pickNextMixed(context.Background(), []string{"claude"}, "claude-opus-5-5", cliproxyexecutor.Options{}, nil)
				} else {
					selected, _, err = m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, nil)
				}
				if err != nil || selected == nil || selected.ID != a.ID || e.checks.Load() != 1 {
					t.Fatalf("selected=%v err=%v checks=%d", selected, err, e.checks.Load())
				}
			})
		}
	}
}

func TestQuotaRecoveryExecutesSameRequest(t *testing.T) {
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	m, a := newQuotaRecoveryManager(t, e)
	markClaudeQuota(m, a.ID, "claude-opus-5-5", 2*time.Hour, false)
	response, err := m.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: "claude-opus-5-5", Payload: []byte(`{}`)}, cliproxyexecutor.Options{})
	if err != nil || string(response.Payload) != `{"ok":true}` || e.calls.Load() != 1 {
		t.Fatalf("response=%s err=%v calls=%d", response.Payload, err, e.calls.Load())
	}
}

func TestQuotaRecoveryThrottlesFailuresAndRechecksAfterInterval(t *testing.T) {
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}}
	m, a := newQuotaRecoveryManager(t, e)
	markClaudeQuota(m, a.ID, "claude-opus-5-5", 2*time.Hour, true)
	for i := 0; i < 10; i++ {
		_, _, err := m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, nil)
		if err == nil {
			t.Fatal("unconfirmed cooldown was lifted")
		}
	}
	if e.checks.Load() != 1 {
		t.Fatalf("checks=%d, want 1", e.checks.Load())
	}
	m.quotaRecovery.mu.Lock()
	m.quotaRecovery.calls[a.ID].expires = time.Now().Add(-time.Second)
	m.quotaRecovery.mu.Unlock()
	e.recovered = true
	selected, _, err := m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, nil)
	if err != nil || selected == nil || e.checks.Load() != 2 {
		t.Fatalf("err=%v checks=%d", err, e.checks.Load())
	}
}

func TestQuotaRecoveryPreservesTransientBackoff(t *testing.T) {
	for _, status := range []int{429, 529} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
			m, a := newQuotaRecoveryManager(t, e)
			retry := time.Hour
			resultErr := &Error{HTTPStatus: status, Message: "temporary failure"}
			if status == 429 {
				resultErr.Code = transientRateLimitErrorCode
			}
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", Model: "claude-opus-5-5", RetryAfter: &retry, Error: resultErr})
			m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, nil)
			if e.checks.Load() != 0 {
				t.Fatalf("checks=%d, want no quota recovery", e.checks.Load())
			}
			updated, _ := m.GetByID(a.ID)
			if len(CooldownSnapshotForAuth(updated, time.Now())) == 0 {
				t.Fatal("transient backoff erased")
			}
		})
	}
}

func TestQuotaRecoveryDoesNotRecheckHealthyOrAlreadyTriedCredentials(t *testing.T) {
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	m, a := newQuotaRecoveryManager(t, e)
	if _, _, err := m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, nil); err != nil {
		t.Fatal(err)
	}
	markClaudeQuota(m, a.ID, "claude-opus-5-5", 2*time.Hour, true)
	m.pickNext(context.Background(), "claude", "claude-opus-5-5", cliproxyexecutor.Options{}, map[string]struct{}{a.ID: {}})
	if e.checks.Load() != 0 {
		t.Fatalf("checks=%d, want no checks", e.checks.Load())
	}
}

func TestQuotaRecoverySharesChecksAndRespectsCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, check: func(context.Context, *Auth, []string) bool {
		close(started)
		<-release
		return true
	}}
	m, a := newQuotaRecoveryManager(t, e)
	markClaudeQuota(m, a.ID, "claude-opus-5-5", 2*time.Hour, true)
	snapshot, _ := m.GetByID(a.ID)
	ctx, cancel := context.WithCancel(context.Background())
	first := m.startQuotaRecovery(ctx, snapshot, []string{"claude-opus-5-5"}, e)
	<-started
	second := m.startQuotaRecovery(context.Background(), snapshot, []string{"claude-opus-5-5"}, e)
	if first != second {
		t.Fatal("concurrent callers did not share the lookup")
	}
	cancel()
	if reset := m.RecoverQuotaCooldowns(ctx); len(reset) != 0 {
		t.Fatal("canceled caller should not wait")
	}
	close(release)
	<-second.ready
	if !second.recovered || e.checks.Load() != 1 {
		t.Fatalf("recovered=%v checks=%d", second.recovered, e.checks.Load())
	}
}

func TestQuotaRecoveryNeverClearsNewerFailures(t *testing.T) {
	for _, status := range []int{401, 429, 529} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, check: func(context.Context, *Auth, []string) bool { close(started); <-release; return true }}
			m, a := newQuotaRecoveryManager(t, e)
			markClaudeQuota(m, a.ID, "claude-opus-5-5", time.Hour, true)
			snapshot, _ := m.GetByID(a.ID)
			call := m.startQuotaRecovery(context.Background(), snapshot, []string{"claude-opus-5-5"}, e)
			<-started
			retry := 3 * time.Hour
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", Model: "claude-opus-5-5", RetryAfter: &retry, Error: &Error{HTTPStatus: status, Message: "newer failure"}})
			close(release)
			<-call.ready
			if call.recovered {
				t.Fatal("stale usage check erased a newer failure")
			}
			updated, _ := m.GetByID(a.ID)
			if state := existingModelState(updated, "claude-opus-5-5"); state == nil || state.LastError == nil || state.LastError.HTTPStatus != status {
				t.Fatal("new failure was erased")
			}
		})
	}
}

func TestQuotaRecoveryBoundsGlobalConcurrencyAndAdvancesThroughPool(t *testing.T) {
	started, release := make(chan struct{}, 10), make(chan struct{})
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, check: func(context.Context, *Auth, []string) bool { started <- struct{}{}; <-release; return false }}
	m, a := newQuotaRecoveryManager(t, e)
	markClaudeQuota(m, a.ID, "claude-opus-5-5", time.Hour, true)
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("extra-%s-%d", a.ID, i)
		if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "claude"}); err != nil {
			t.Fatal(err)
		}
		markClaudeQuota(m, id, "claude-opus-5-5", time.Hour, true)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.RecoverQuotaCooldowns(context.Background()) }()
	}
	for i := 0; i < quotaRecoveryMaxConcurrent; i++ {
		<-started
	}
	if e.checks.Load() != quotaRecoveryMaxConcurrent {
		t.Fatalf("checks=%d", e.checks.Load())
	}
	close(release)
	wg.Wait()
	// Completed entries remain throttled, allowing another pass to reach the rest.
	m.RecoverQuotaCooldowns(context.Background())
	if e.checks.Load() <= quotaRecoveryMaxConcurrent {
		t.Fatal("later candidates starved behind throttled entries")
	}
}

func TestQuotaRecoveryUsesReadyAccountWithoutWaitingForSlowAccount(t *testing.T) {
	slowStarted, release := make(chan struct{}), make(chan struct{})
	var slowID string
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, check: func(_ context.Context, a *Auth, _ []string) bool {
		if a.ID == slowID {
			close(slowStarted)
			<-release
			return false
		}
		<-slowStarted
		return true
	}}
	m, a := newQuotaRecoveryManager(t, e)
	slowID = a.ID
	markClaudeQuota(m, a.ID, "claude-opus-5-5", time.Hour, true)
	fastID := "z-" + a.ID
	if _, err := m.Register(context.Background(), &Auth{ID: fastID, Provider: "claude"}); err != nil {
		t.Fatal(err)
	}
	markClaudeQuota(m, fastID, "claude-opus-5-5", time.Hour, true)
	t.Cleanup(func() {
		close(release)
		m.quotaRecovery.mu.Lock()
		call := m.quotaRecovery.calls[slowID]
		m.quotaRecovery.mu.Unlock()
		if call != nil {
			<-call.ready
		}
	})
	if reset := m.RecoverQuotaCooldowns(context.Background()); len(reset) != 1 || reset[0] != fastID {
		t.Fatalf("reset=%v, want ready account without waiting for slow one", reset)
	}
}

func TestQuotaRecoveryPreservesHiddenNonQuotaBackoff(t *testing.T) {
	for _, status := range []int{429, 529} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
			m, a := newQuotaRecoveryManager(t, e)
			retry := time.Hour
			resultErr := &Error{HTTPStatus: status, Message: "temporary failure"}
			if status == 429 {
				resultErr.Code = transientRateLimitErrorCode
			}
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", Model: "claude-opus-5-5", RetryAfter: &retry, Error: resultErr})
			markClaudeQuota(m, a.ID, "claude-fable-5-2", 2*time.Hour, true)
			before, _ := m.GetByID(a.ID)
			state := existingModelState(before, "claude-opus-5-5")
			if state == nil || state.credentialQuotaShadow == nil || state.credentialQuotaShadow.LastError == nil || state.credentialQuotaShadow.LastError.HTTPStatus != status {
				t.Fatal("setup failed: expected live independent non-quota shadow")
			}
			t.Logf("before views=%+v", CooldownSnapshotForAuth(before, time.Now()))
			reset := m.RecoverQuotaCooldowns(context.Background())
			after, _ := m.GetByID(a.ID)
			t.Logf("reset=%v checks=%d after=%+v", reset, e.checks.Load(), CooldownSnapshotForAuth(after, time.Now()))
			if len(reset) > 0 || e.checks.Load() != 0 {
				t.Fatal("automatic quota recovery must skip live independent non-quota backoff")
			}
			if _, ok := longQuotaCooldownModels(before, time.Now().Add(90*time.Minute)); !ok {
				t.Fatal("expired independent backoff should no longer prevent quota recovery")
			}
			if len(CooldownSnapshotForAuth(after, time.Now())) == 0 {
				t.Fatal("quota restrictions were erased")
			}
			preserved := existingModelState(after, "claude-opus-5-5")
			if preserved == nil || preserved.credentialQuotaShadow == nil || !preserved.credentialQuotaShadow.NextRetryAfter.Equal(state.credentialQuotaShadow.NextRetryAfter) {
				t.Fatal("independent retry deadline changed")
			}

		})
	}
}

func TestQuotaRecoveryCanClearIndependentQuotaShadow(t *testing.T) {
	e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, recovered: true}
	m, a := newQuotaRecoveryManager(t, e)
	markClaudeQuota(m, a.ID, "claude-opus-5-5", time.Hour, false)
	markClaudeQuota(m, a.ID, "claude-fable-5-2", 2*time.Hour, true)
	if reset := m.RecoverQuotaCooldowns(context.Background()); len(reset) != 1 || e.checks.Load() != 1 {
		t.Fatalf("reset=%v checks=%d, want confirmed recovery of both quota layers", reset, e.checks.Load())
	}
	if len(e.models) != 2 {
		t.Fatalf("checked models=%v, want both cooled models", e.models)
	}
}

func TestQuotaRecoveryNeverClearsReplacementCredential(t *testing.T) {
	for _, reregister := range []bool{false, true} {
		t.Run(fmt.Sprintf("reregister=%v", reregister), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			e := &quotaRecoveryExecutor{successExecutor: successExecutor{provider: "claude"}, check: func(context.Context, *Auth, []string) bool { close(started); <-release; return true }}
			m, a := newQuotaRecoveryManager(t, e)
			markClaudeQuota(m, a.ID, "claude-opus-5-5", time.Hour, true)
			before, _ := m.GetByID(a.ID)
			call := m.startQuotaRecovery(context.Background(), before, []string{"claude-opus-5-5"}, e)
			<-started
			var changed *Auth
			var err error
			if reregister {
				m.Remove(context.Background(), a.ID)
				changed, err = m.Register(context.Background(), &Auth{ID: a.ID, Provider: "claude", Attributes: map[string]string{"api_key": "new-key"}})
			} else {
				updated := before.Clone()
				updated.Attributes["api_key"] = "new-key"
				changed, err = m.Update(context.Background(), updated)
			}
			if err != nil {
				close(release)
				<-call.ready
				t.Fatal(err)
			}
			retry := 3 * time.Hour
			m.MarkResult(context.Background(), Result{
				AuthID: a.ID, Provider: "claude", Model: "claude-opus-5-5",
				CredentialVersion: changed.CredentialVersion, RegistrationEpoch: changed.RegistrationEpoch,
				RetryAfter: &retry, CredentialScope: true,
				Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "new credential quota"},
			})
			close(release)
			<-call.ready
			if call.recovered {
				t.Fatal("usage for old credentials cleared replacement cooldown")
			}
			if reregister && changed.RegistrationEpoch == before.RegistrationEpoch {
				t.Fatal("test did not advance registration epoch")
			}
			if !reregister && changed.CredentialVersion == before.CredentialVersion {
				t.Fatal("test did not advance credential version")
			}
			after, _ := m.GetByID(a.ID)
			if !after.Quota.Exceeded || after.Quota.NextRecoverAt.Sub(time.Now()) < 2*time.Hour {
				t.Fatal("replacement cooldown was cleared")
			}
		})
	}
}
