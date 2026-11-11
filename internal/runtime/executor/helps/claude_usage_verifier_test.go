package helps

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testClaudeOAuthToken = "sk-ant-oat01-test"

func TestClaudeUsageVerdictFromBody(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		model string
		want  ClaudeUsageVerdict
	}{
		{
			name:  "weekly window with room",
			body:  `{"five_hour":null,"seven_day":{"utilization":77.0,"resets_at":"2026-11-15T01:59:59Z"},"seven_day_opus":null,"extra_usage":{"is_enabled":false,"utilization":100}}`,
			model: "claude-fable-5-2",
			want:  ClaudeUsageAvailable,
		},
		{
			name:  "weekly window used up",
			body:  `{"five_hour":null,"seven_day":{"utilization":100.0}}`,
			model: "claude-fable-5-2",
			want:  ClaudeUsageExhausted,
		},
		{
			name:  "session window used up",
			body:  `{"five_hour":{"utilization":100.0},"seven_day":{"utilization":10.0}}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageExhausted,
		},
		{
			name:  "locked window counts as used up",
			body:  `{"five_hour":null,"seven_day":{"utilization":40.0,"locked_reason":"policy"}}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageExhausted,
		},
		{
			name:  "family window used up for that family",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"seven_day_opus":{"utilization":100}}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageModelExhausted,
		},
		{
			name:  "family window used up for another family",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"seven_day_opus":{"utilization":100}}`,
			model: "claude-sonnet-5",
			want:  ClaudeUsageAvailable,
		},
		{
			name:  "family window used up for an unrecognised model",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"seven_day_opus":{"utilization":100}}`,
			model: "claude-mythos-1",
			want:  ClaudeUsageUnknown,
		},
		{
			name:  "unrecognised window used up",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"amber_ladder":{"utilization":100}}`,
			model: "claude-fable-5-2",
			want:  ClaudeUsageUnknown,
		},
		{
			name:  "model-scoped limit matches display name",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"limits":[{"percent":100,"scope":{"model":{"display_name":"Fable 5.2"}}}]}`,
			model: "claude-fable-5-2",
			want:  ClaudeUsageModelExhausted,
		},
		{
			name:  "model-scoped limit for another family",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"limits":[{"percent":100,"scope":{"model":{"display_name":"Fable 5.2"}}}]}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageAvailable,
		},
		{
			name:  "unscoped limit used up",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"limits":[{"percent":100,"scope":null}]}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageExhausted,
		},
		{
			name:  "surface-scoped limit used up",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"limits":[{"percent":100,"scope":{"surface":"desktop"}}]}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageUnknown,
		},
		{
			name:  "limit under 100 percent",
			body:  `{"five_hour":null,"seven_day":{"utilization":50},"limits":[{"percent":99.5,"scope":null}]}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageAvailable,
		},
		{
			name:  "missing weekly window",
			body:  `{"five_hour":null}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageUnknown,
		},
		{
			name:  "non-numeric utilization",
			body:  `{"five_hour":null,"seven_day":{"utilization":"77"}}`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageUnknown,
		},
		{
			name:  "invalid JSON",
			body:  `{"seven_day":`,
			model: "claude-opus-5-5",
			want:  ClaudeUsageUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClaudeUsageVerdictFromBody([]byte(tt.body), tt.model); got != tt.want {
				t.Fatalf("verdict = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestClaudeUsageVerifierCachesAndSharesLookups(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	release := make(chan struct{})
	verifier := &ClaudeUsageVerifier{
		NowFunc: func() time.Time { return now },
		Fetch: func(context.Context, *http.Client, string, string) []byte {
			calls.Add(1)
			<-release
			return []byte(`{"five_hour":null,"seven_day":{"utilization":10}}`)
		},
	}

	var wg sync.WaitGroup
	results := make([]ClaudeUsageVerdict, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = verifier.Verdict(context.Background(), http.DefaultClient, testClaudeOAuthToken, "", "claude-opus-5-5")
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	for i, got := range results {
		if got != ClaudeUsageAvailable {
			t.Fatalf("caller %d verdict = %s, want available", i, got)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent lookups = %d, want 1", got)
	}

	verifier.Verdict(context.Background(), http.DefaultClient, testClaudeOAuthToken, "", "claude-opus-5-5")
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookups within cache TTL = %d, want 1", got)
	}
	now = now.Add(claudeUsageCacheTTL + time.Second)
	verifier.Verdict(context.Background(), http.DefaultClient, testClaudeOAuthToken, "", "claude-opus-5-5")
	if got := calls.Load(); got != 2 {
		t.Fatalf("lookups after cache TTL = %d, want 2", got)
	}
}

func TestClaudeUsageVerifierSkipsNonOAuthTokensAndFailedLookups(t *testing.T) {
	var calls atomic.Int32
	verifier := &ClaudeUsageVerifier{Fetch: func(context.Context, *http.Client, string, string) []byte {
		calls.Add(1)
		return nil
	}}
	if got := verifier.Verdict(context.Background(), http.DefaultClient, "sk-ant-api03-key", "", "claude-opus-5-5"); got != ClaudeUsageUnknown {
		t.Fatalf("API key verdict = %s, want unknown", got)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("API key triggered %d lookups, want 0", got)
	}
	if got := verifier.Verdict(context.Background(), http.DefaultClient, testClaudeOAuthToken, "", "claude-opus-5-5"); got != ClaudeUsageUnknown {
		t.Fatalf("failed lookup verdict = %s, want unknown", got)
	}
}

func TestClaudeUsageVerifierContradictionBackoffEscalatesAndResets(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	verifier := &ClaudeUsageVerifier{NowFunc: func() time.Time { return now }}
	want := []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, time.Hour, time.Hour}
	for i, expected := range want {
		if got := verifier.ContradictionRetryAfter("auth-a", "claude-fable-5-2"); got != expected {
			t.Fatalf("contradiction %d backoff = %s, want %s", i+1, got, expected)
		}
		now = now.Add(time.Minute)
	}
	if got := verifier.ContradictionRetryAfter("auth-b", "claude-fable-5-2"); got != 30*time.Second {
		t.Fatalf("other auth backoff = %s, want 30s", got)
	}
	now = now.Add(claudeContradictionWindow + time.Minute)
	if got := verifier.ContradictionRetryAfter("auth-a", "claude-fable-5-2"); got != 30*time.Second {
		t.Fatalf("backoff after quiet window = %s, want 30s", got)
	}
}

func TestClaudeOverloadRetryAfterIgnoresQuotaResetHeaders(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	headers := http.Header{
		"Anthropic-Ratelimit-Unified-Status": []string{"rejected"},
		"Anthropic-Ratelimit-Unified-Reset":  []string{"1800259200"},
	}
	if got := ClaudeOverloadRetryAfter(headers, now); got != nil {
		t.Fatalf("529 without Retry-After = %s, want nil", *got)
	}
	headers.Set("Retry-After", "20")
	got := ClaudeOverloadRetryAfter(headers, now)
	if got == nil || *got != 20*time.Second {
		t.Fatalf("529 retry = %v, want 20s", got)
	}
}
