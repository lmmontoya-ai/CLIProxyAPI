package executor

import (
	"context"
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const claudeUsageTestBody = `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your account's rate limit. Please try again later."}}`

func newClaudeUsageTestExecutor(usage string, calls *atomic.Int32) *ClaudeExecutor {
	executor := NewClaudeExecutor(nil)
	executor.oauthUsageVerifier.Fetch = func(context.Context, *http.Client, string, string) []byte {
		calls.Add(1)
		if usage == "" {
			return nil
		}
		return []byte(usage)
	}
	return executor
}

func claudeUsageTestAuth(token string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{ID: "claude-usage-test", Provider: "claude", Attributes: map[string]string{"api_key": token}}
}

func claudeUsageTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?beta=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "claude-cli/2.1.322 (external, cli)")
	return req
}

func weeklyRejection429() *http.Response {
	reset := strconv.FormatInt(time.Now().Add(75*time.Hour).Unix(), 10)
	return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{
		"Anthropic-Ratelimit-Unified-Status":    []string{"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Status": []string{"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Reset":  []string{reset},
		"Anthropic-Ratelimit-Unified-Reset":     []string{reset},
	}}
}

func errorScope(t *testing.T, err error) (credentialScoped, transient bool, retryAfter *time.Duration) {
	t.Helper()
	if cs, ok := err.(interface{ IsCredentialScoped() bool }); ok {
		credentialScoped = cs.IsCredentialScoped()
	}
	var tr cliproxyexecutor.TransientRateLimitError
	transient = errors.As(err, &tr) && tr.IsTransientRateLimit()
	if rap, ok := err.(interface{ RetryAfter() *time.Duration }); ok {
		retryAfter = rap.RetryAfter()
	}
	return
}

func TestClaudeClassifyUpstreamError_UsageWithRoomDowngradesWeeklyLockout(t *testing.T) {
	var calls atomic.Int32
	executor := newClaudeUsageTestExecutor(`{"five_hour":null,"seven_day":{"utilization":77}}`, &calls)
	auth := claudeUsageTestAuth("sk-ant-oat01-test")

	err := executor.classifyUpstreamError(context.Background(), auth, claudeUsageTestRequest(t), weeklyRejection429(), []byte(claudeUsageTestBody), "claude-fable-5-2", false)
	credentialScoped, transient, retryAfter := errorScope(t, err)
	if credentialScoped || !transient {
		t.Fatalf("credentialScoped=%v transient=%v, want a model-only transient 429", credentialScoped, transient)
	}
	if retryAfter == nil || *retryAfter != 30*time.Second {
		t.Fatalf("retryAfter = %v, want 30s", retryAfter)
	}

	err = executor.classifyUpstreamError(context.Background(), auth, claudeUsageTestRequest(t), weeklyRejection429(), []byte(claudeUsageTestBody), "claude-fable-5-2", false)
	if _, _, retryAfter = errorScope(t, err); retryAfter == nil || *retryAfter != 2*time.Minute {
		t.Fatalf("repeated contradiction retryAfter = %v, want 2m", retryAfter)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("usage lookups = %d, want 1 (cached)", got)
	}
}

func TestClaudeClassifyUpstreamError_ExhaustedOrUnknownUsageKeepsLockout(t *testing.T) {
	for name, usage := range map[string]string{
		"exhausted": `{"five_hour":null,"seven_day":{"utilization":100}}`,
		"unknown":   "",
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			executor := newClaudeUsageTestExecutor(usage, &calls)
			err := executor.classifyUpstreamError(context.Background(), claudeUsageTestAuth("sk-ant-oat01-test"), claudeUsageTestRequest(t), weeklyRejection429(), []byte(claudeUsageTestBody), "claude-fable-5-2", false)
			credentialScoped, transient, retryAfter := errorScope(t, err)
			if !credentialScoped || transient {
				t.Fatalf("credentialScoped=%v transient=%v, want the credential-wide cooldown kept", credentialScoped, transient)
			}
			if retryAfter == nil || *retryAfter < 74*time.Hour {
				t.Fatalf("retryAfter = %v, want the weekly reset", retryAfter)
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("usage lookups = %d, want 1", got)
			}
		})
	}
}

func TestClaudeClassifyUpstreamError_ModelOnlyExhaustionStaysOnModel(t *testing.T) {
	var calls atomic.Int32
	executor := newClaudeUsageTestExecutor(`{"five_hour":null,"seven_day":{"utilization":50},"seven_day_fable":{"utilization":100}}`, &calls)
	err := executor.classifyUpstreamError(context.Background(), claudeUsageTestAuth("sk-ant-oat01-test"), claudeUsageTestRequest(t), weeklyRejection429(), []byte(claudeUsageTestBody), "claude-fable-5-2", false)
	credentialScoped, transient, retryAfter := errorScope(t, err)
	if credentialScoped || transient {
		t.Fatalf("credentialScoped=%v transient=%v, want a model-scoped quota cooldown", credentialScoped, transient)
	}
	if retryAfter == nil || *retryAfter < 74*time.Hour {
		t.Fatalf("retryAfter = %v, want the weekly reset kept on the model", retryAfter)
	}
}

func TestClaudeClassifyUpstreamError_SkipsUsageLookupWhenItCannotHelp(t *testing.T) {
	shortRetry := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"20"}}}
	tests := []struct {
		name  string
		token string
		resp  *http.Response
	}{
		{name: "short retry", token: "sk-ant-oat01-test", resp: shortRetry},
		{name: "API key", token: "sk-ant-api03-key", resp: weeklyRejection429()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			executor := newClaudeUsageTestExecutor(`{"five_hour":null,"seven_day":{"utilization":10}}`, &calls)
			err := executor.classifyUpstreamError(context.Background(), claudeUsageTestAuth(tt.token), claudeUsageTestRequest(t), tt.resp, []byte(claudeUsageTestBody), "claude-opus-5-5", false)
			if got := calls.Load(); got != 0 {
				t.Fatalf("usage lookups = %d, want 0", got)
			}
			if tt.resp.StatusCode == 529 {
				_, _, retryAfter := errorScope(t, err)
				if retryAfter == nil || *retryAfter != 15*time.Second {
					t.Fatalf("529 retryAfter = %v, want Retry-After only (15s)", retryAfter)
				}
			}
		})
	}
}

func TestClaudeClassifyUpstreamError_FastRequestWithRoomIsNotCredentialScoped(t *testing.T) {
	var calls atomic.Int32
	executor := newClaudeUsageTestExecutor(`{"five_hour":null,"seven_day":{"utilization":10}}`, &calls)
	err := executor.classifyUpstreamError(context.Background(), claudeUsageTestAuth("sk-ant-oat01-test"), claudeUsageTestRequest(t), weeklyRejection429(), []byte(claudeUsageTestBody), "claude-opus-5-5", true)
	var fast *claudeFastDirectResponseError
	if !errors.As(err, &fast) {
		t.Fatalf("err = %T, want fast direct response error", err)
	}
	if fast.IsCredentialScoped() {
		t.Fatal("fast 429 stayed credential-scoped although usage shows room")
	}
}

func TestClaudeExecutorQuotaRecovered(t *testing.T) {
	for name, tt := range map[string]struct {
		usage  string
		token  string
		models []string
		want   bool
	}{
		"room for every model":  {usage: `{"five_hour":null,"seven_day":{"utilization":40}}`, token: "sk-ant-oat01-test", models: []string{"claude-fable-5-2", "claude-opus-5-5"}, want: true},
		"one model capped":      {usage: `{"five_hour":null,"seven_day":{"utilization":40},"seven_day_opus":{"utilization":100}}`, token: "sk-ant-oat01-test", models: []string{"claude-fable-5-2", "claude-opus-5-5"}, want: false},
		"credential-only block": {usage: `{"five_hour":null,"seven_day":{"utilization":40}}`, token: "sk-ant-oat01-test", want: true},
		"weekly used up":        {usage: `{"five_hour":null,"seven_day":{"utilization":100}}`, token: "sk-ant-oat01-test", models: []string{"claude-opus-5-5"}, want: false},
		"lookup failed":         {token: "sk-ant-oat01-test", models: []string{"claude-opus-5-5"}, want: false},
		"API key":               {usage: `{"five_hour":null,"seven_day":{"utilization":40}}`, token: "sk-ant-api03-key", models: []string{"claude-opus-5-5"}, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			executor := newClaudeUsageTestExecutor(tt.usage, &calls)
			if got := executor.QuotaRecovered(context.Background(), claudeUsageTestAuth(tt.token), tt.models); got != tt.want {
				t.Fatalf("QuotaRecovered = %v, want %v", got, tt.want)
			}
		})
	}
}

var _ cliproxyauth.QuotaRecoveryChecker = (*ClaudeExecutor)(nil)

func TestClaudeClassifyOverloadChecksUsageWithoutErasingOverload(t *testing.T) {
	for name, usage := range map[string]string{
		"available":   `{"five_hour":null,"seven_day":{"utilization":10}}`,
		"exhausted":   `{"five_hour":null,"seven_day":{"utilization":100}}`,
		"unavailable": "",
	} {
		for _, fast := range []bool{false, true} {
			t.Run(name+strconv.FormatBool(fast), func(t *testing.T) {
				var calls atomic.Int32
				e := newClaudeUsageTestExecutor(usage, &calls)
				response := weeklyRejection429()
				response.StatusCode = 529
				response.Header.Set("Retry-After", "15")
				for i := 0; i < 5; i++ {
					err := e.classifyUpstreamError(context.Background(), claudeUsageTestAuth("sk-ant-oat01-test"), claudeUsageTestRequest(t), response, []byte(`{"error":{"type":"overloaded_error","message":"Overloaded"}}`), "claude-opus-5-5", fast)
					cs, tr, retry := errorScope(t, err)
					var status interface{ StatusCode() int }
					retryOK := retry != nil && *retry == 15*time.Second
					if fast {
						var direct *cliproxyexecutor.RequestTerminatedError
						retryOK = retry == nil && errors.As(err, &direct) && direct.ResponseHeaders().Get("Retry-After") == "15"
					}
					if !errors.As(err, &status) || status.StatusCode() != 529 || cs || tr || !retryOK {
						t.Fatalf("overload altered: %T %v scope=%v transient=%v retry=%v", err, err, cs, tr, retry)
					}
				}
				e.oauthUsageVerifier.Verdict(context.Background(), http.DefaultClient, "sk-ant-oat01-test", "", "claude-opus-5-5")
				if calls.Load() != 1 {
					t.Fatalf("usage calls=%d, want cached single lookup", calls.Load())
				}
			})
		}
	}
}

func TestClaudeClassifyOverloadDoesNotWaitForUsage(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	e := NewClaudeExecutor(nil)
	e.oauthUsageVerifier.Fetch = func(context.Context, *http.Client, string, string) []byte {
		close(started)
		<-release
		return []byte(`{"five_hour":null,"seven_day":{"utilization":10}}`)
	}
	response := weeklyRejection429()
	response.StatusCode = 529
	response.Header.Set("Retry-After", "15")
	req := claudeUsageTestRequest(t)
	result := make(chan error, 1)
	go func() {
		result <- e.classifyUpstreamError(context.Background(), claudeUsageTestAuth("sk-ant-oat01-test"), req, response, []byte(`{"error":{"type":"overloaded_error"}}`), "claude-opus-5-5", false)
	}()
	<-started
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-result:
		if _, _, retry := errorScope(t, err); retry == nil || *retry != 15*time.Second {
			close(release)
			t.Fatal("overload retry changed")
		}
	case <-timer.C:
		close(release)
		t.Fatal("529 failover waited for usage fetch")
	}
	close(release)
	if got := e.oauthUsageVerifier.Verdict(context.Background(), http.DefaultClient, "sk-ant-oat01-test", "", "claude-opus-5-5"); got != helps.ClaudeUsageAvailable {
		t.Fatalf("background usage=%s", got)
	}
}

func TestClaudeUsageProbeDefersWhenLookupSlotsAreFull(t *testing.T) {
	started, release := make(chan struct{}, 4), make(chan struct{})
	e := NewClaudeExecutor(nil)
	var calls atomic.Int32
	e.oauthUsageVerifier.Fetch = func(context.Context, *http.Client, string, string) []byte {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return []byte(`{"five_hour":null,"seven_day":{"utilization":10}}`)
	}
	var wg sync.WaitGroup
	for _, token := range []string{"sk-ant-oat01-a", "sk-ant-oat01-b", "sk-ant-oat01-c"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.oauthUsageVerifier.Verdict(context.Background(), http.DefaultClient, token, "", "claude-opus-5-5")
		}()
	}
	<-started
	<-started
	<-started
	auth := claudeUsageTestAuth("sk-ant-oat01-deferred")
	got := e.ProbeQuotaRecovery(context.Background(), auth, []string{"claude-opus-5-5"})
	close(release)
	wg.Wait()
	if got != cliproxyauth.QuotaRecoveryDeferred {
		t.Fatalf("saturated probe=%v, want deferred", got)
	}
	if got = e.ProbeQuotaRecovery(context.Background(), auth, []string{"claude-opus-5-5"}); got != cliproxyauth.QuotaRecoveryConfirmed {
		t.Fatalf("subsequent probe=%v, want confirmed", got)
	}
	if calls.Load() != 4 {
		t.Fatalf("calls=%d, want no cached failure for skipped check", calls.Load())
	}
}

var _ cliproxyauth.QuotaRecoveryProber = (*ClaudeExecutor)(nil)
