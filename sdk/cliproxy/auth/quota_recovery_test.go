package auth

import (
	"context"
	"net/http"
	"sync/atomic"
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
}

func (e *quotaRecoveryExecutor) QuotaRecovered(_ context.Context, _ *Auth, models []string) bool {
	e.checks.Add(1)
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
	markClaudeQuota(manager, auth.ID, "claude-opus-5-5", 2*time.Minute, false)
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
