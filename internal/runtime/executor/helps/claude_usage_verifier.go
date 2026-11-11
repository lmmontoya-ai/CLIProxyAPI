package helps

import (
	"context"
	"crypto/sha256"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MoeForge/moego/ojson"
	log "github.com/sirupsen/logrus"
)

// ClaudeUsageVerdict is the result of comparing a model against a live
// Claude subscription usage snapshot.
type ClaudeUsageVerdict int

const (
	// ClaudeUsageUnknown means the snapshot was unavailable or could not be
	// interpreted with confidence. Callers must keep their original decision.
	ClaudeUsageUnknown ClaudeUsageVerdict = iota
	// ClaudeUsageAvailable means every applicable window positively shows room.
	ClaudeUsageAvailable
	// ClaudeUsageExhausted means a shared subscription window is used up, so
	// every model on the account is blocked.
	ClaudeUsageExhausted
	// ClaudeUsageModelExhausted means only a window specific to this model or
	// its family is used up; other models on the account still have room.
	ClaudeUsageModelExhausted
)

func (v ClaudeUsageVerdict) String() string {
	switch v {
	case ClaudeUsageAvailable:
		return "available"
	case ClaudeUsageExhausted:
		return "exhausted"
	case ClaudeUsageModelExhausted:
		return "model_exhausted"
	default:
		return "unknown"
	}
}

const (
	claudeUsageURL            = "https://api.anthropic.com/api/oauth/usage"
	claudeUsageCacheTTL       = 30 * time.Second
	claudeUsageFetchTimeout   = 3 * time.Second
	claudeUsageMaxEntries     = 256
	claudeUsageMaxBody        = 64 * 1024
	claudeContradictionWindow = 2 * time.Hour
)

// claudeContradictionBackoff escalates the model-only cooldown applied while
// live usage keeps contradicting Anthropic 429s. A hidden or newly introduced
// limit therefore cannot cause a tight retry loop.
var claudeContradictionBackoff = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
	time.Hour,
}

type claudeUsageCheck struct {
	ready   chan struct{}
	expires time.Time
	body    []byte
}

type claudeContradiction struct {
	count int
	last  time.Time
}

// ClaudeUsageFetcher fetches the raw usage JSON for one OAuth access token.
// It returns nil when the lookup failed.
type ClaudeUsageFetcher func(ctx context.Context, client *http.Client, accessToken, userAgent string) []byte

// ClaudeUsageVerifier checks first-party Claude OAuth subscription usage.
// Lookups are cached briefly and shared between concurrent callers. Tokens
// and usage payloads are never logged or persisted.
type ClaudeUsageVerifier struct {
	mu             sync.Mutex
	checks         map[[32]byte]*claudeUsageCheck
	contradictions map[string]*claudeContradiction

	// NowFunc and Fetch are test seams; nil uses the real clock and endpoint.
	NowFunc func() time.Time
	Fetch   ClaudeUsageFetcher
}

func (v *ClaudeUsageVerifier) now() time.Time {
	if v.NowFunc != nil {
		return v.NowFunc()
	}
	return time.Now()
}

// IsClaudeOAuthAccessToken reports whether token is a Claude subscription
// OAuth access token rather than a Console API key.
func IsClaudeOAuthAccessToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), "sk-ant-oat")
}

// Verdict compares model against the account's live usage.
func (v *ClaudeUsageVerifier) Verdict(ctx context.Context, client *http.Client, accessToken, userAgent, model string) ClaudeUsageVerdict {
	if v == nil || client == nil || !IsClaudeOAuthAccessToken(accessToken) {
		return ClaudeUsageUnknown
	}
	body := v.snapshot(ctx, client, accessToken, userAgent)
	if body == nil {
		return ClaudeUsageUnknown
	}
	return ClaudeUsageVerdictFromBody(body, model)
}

// ContradictionRetryAfter records that Anthropic rejected authID/model while
// live usage showed room, and returns the escalating model-only cooldown.
func (v *ClaudeUsageVerifier) ContradictionRetryAfter(authID, model string) time.Duration {
	if v == nil {
		return claudeContradictionBackoff[0]
	}
	key := authID + "\x00" + strings.ToLower(strings.TrimSpace(model))
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.contradictions == nil {
		v.contradictions = make(map[string]*claudeContradiction)
	}
	for k, entry := range v.contradictions {
		if now.Sub(entry.last) > claudeContradictionWindow {
			delete(v.contradictions, k)
		}
	}
	entry := v.contradictions[key]
	if entry == nil {
		if len(v.contradictions) >= claudeUsageMaxEntries {
			return claudeContradictionBackoff[len(claudeContradictionBackoff)-1]
		}
		entry = &claudeContradiction{}
		v.contradictions[key] = entry
	}
	step := entry.count
	if step >= len(claudeContradictionBackoff) {
		step = len(claudeContradictionBackoff) - 1
	}
	entry.count++
	entry.last = now
	return claudeContradictionBackoff[step]
}

func (v *ClaudeUsageVerifier) snapshot(ctx context.Context, client *http.Client, accessToken, userAgent string) []byte {
	key := sha256.Sum256([]byte(accessToken))
	now := v.now()
	v.mu.Lock()
	if entry := v.checks[key]; entry != nil {
		select {
		case <-entry.ready:
			if now.Before(entry.expires) {
				v.mu.Unlock()
				return entry.body
			}
		default:
			v.mu.Unlock()
			select {
			case <-entry.ready:
				return entry.body
			case <-ctx.Done():
				return nil
			}
		}
	}
	if v.checks == nil {
		v.checks = make(map[[32]byte]*claudeUsageCheck)
	}
	for k, entry := range v.checks {
		select {
		case <-entry.ready:
			if !now.Before(entry.expires) {
				delete(v.checks, k)
			}
		default:
		}
	}
	if len(v.checks) >= claudeUsageMaxEntries {
		v.mu.Unlock()
		return nil
	}
	entry := &claudeUsageCheck{ready: make(chan struct{})}
	v.checks[key] = entry
	v.mu.Unlock()

	fetch := v.Fetch
	if fetch == nil {
		fetch = fetchClaudeUsage
	}
	// The lookup must not inherit one request's cancellation: other callers may
	// be waiting on it. Its own timeout bounds it instead.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), claudeUsageFetchTimeout)
	body := fetch(fetchCtx, client, accessToken, userAgent)
	cancel()

	v.mu.Lock()
	entry.body = body
	entry.expires = v.now().Add(claudeUsageCacheTTL)
	close(entry.ready)
	v.mu.Unlock()
	return body
}

func fetchClaudeUsage(ctx context.Context, client *http.Client, accessToken, userAgent string) []byte {
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, claudeUsageURL, nil)
	if errRequest != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	req.Header.Set("Accept", "application/json")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	usageClient := *client
	usageClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, errFetch := usageClient.Do(req)
	if errFetch != nil {
		LogWithRequestID(ctx).Warn("Claude usage lookup failed; keeping upstream cooldown")
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		LogWithRequestID(ctx).WithField("usage_status", resp.StatusCode).Warn("Claude usage lookup unavailable; keeping upstream cooldown")
		return nil
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, claudeUsageMaxBody+1))
	if errRead != nil || len(body) > claudeUsageMaxBody {
		return nil
	}
	return body
}

// Shared subscription windows that gate every model.
var claudeSharedUsageWindows = map[string]bool{
	"five_hour":            true,
	"seven_day":            true,
	"seven_day_oauth_apps": true,
}

// Model-family windows and the family token that identifies their models.
var claudeFamilyUsageWindows = map[string]string{
	"seven_day_opus":   "opus",
	"seven_day_sonnet": "sonnet",
	"seven_day_haiku":  "haiku",
	"seven_day_fable":  "fable",
}

// Paid overage credits are not part of the subscription allowance.
var claudeIgnoredUsageWindows = map[string]bool{
	"extra_usage":   true,
	"promo_credits": true,
}

var claudeKnownFamilies = []string{"opus", "sonnet", "haiku", "fable"}

// ClaudeUsageVerdictFromBody interprets an /api/oauth/usage response. It is
// deliberately fail-safe: an exhausted window that cannot be confidently
// attributed to another model yields Unknown, never Available.
func ClaudeUsageVerdictFromBody(body []byte, model string) ClaudeUsageVerdict {
	if !ojson.ValidBytes(body) {
		return ClaudeUsageUnknown
	}
	root := ojson.ParseBytes(body)
	if !root.IsObject() {
		return ClaudeUsageUnknown
	}
	// The weekly window must be present. A null session window is normal for
	// tiers that only have a weekly allowance.
	if !root.Get("five_hour").Exists() || !root.Get("seven_day").IsObject() {
		return ClaudeUsageUnknown
	}
	normalizedModel := normalizeClaudeModelName(model)
	family := claudeModelFamily(normalizedModel)

	sharedExhausted, modelExhausted, unknown := false, false, false
	root.ForEach(func(key, window ojson.Result) bool {
		name := key.String()
		if claudeIgnoredUsageWindows[name] || !window.IsObject() {
			return true
		}
		utilization := window.Get("utilization")
		if !utilization.Exists() || utilization.Type == ojson.Null {
			// Not a usage window (feature flags, pacing metadata, ...), or an
			// inactive one.
			return true
		}
		if !validClaudeUsagePercent(utilization) {
			unknown = true
			return false
		}
		if utilization.Float() < 100 && window.Get("locked_reason").String() == "" {
			return true
		}
		switch {
		case claudeSharedUsageWindows[name]:
			sharedExhausted = true
		case claudeFamilyUsageWindows[name] != "":
			windowFamily := claudeFamilyUsageWindows[name]
			if family == windowFamily {
				modelExhausted = true
			} else if family == "" {
				unknown = true
			}
		default:
			// An unrecognised window is used up. It may be a per-model cap
			// under an internal name, so it cannot be ruled out.
			unknown = true
		}
		return true
	})
	if sharedExhausted {
		return ClaudeUsageExhausted
	}
	if unknown {
		return ClaudeUsageUnknown
	}

	limits := root.Get("limits")
	if limits.Exists() && limits.Type != ojson.Null {
		if !limits.IsArray() {
			return ClaudeUsageUnknown
		}
		for _, limit := range limits.Array() {
			percent := limit.Get("percent")
			if !validClaudeUsagePercent(percent) {
				return ClaudeUsageUnknown
			}
			if percent.Float() < 100 {
				continue
			}
			switch claudeLimitScopeForModel(limit.Get("scope"), normalizedModel, family) {
			case claudeLimitShared:
				return ClaudeUsageExhausted
			case claudeLimitThisModel:
				modelExhausted = true
			case claudeLimitUnattributed:
				return ClaudeUsageUnknown
			}
		}
	}
	if modelExhausted {
		return ClaudeUsageModelExhausted
	}
	return ClaudeUsageAvailable
}

type claudeLimitScope int

const (
	claudeLimitUnattributed claudeLimitScope = iota
	claudeLimitShared
	claudeLimitThisModel
	claudeLimitOtherModel
)

// claudeLimitScopeForModel attributes an exhausted entry in the limits array
// relative to model.
func claudeLimitScopeForModel(scope ojson.Result, normalizedModel, family string) claudeLimitScope {
	if !scope.Exists() || scope.Type == ojson.Null {
		return claudeLimitShared
	}
	if !scope.IsObject() {
		return claudeLimitUnattributed
	}
	if surface := scope.Get("surface"); surface.Exists() && surface.Type != ojson.Null {
		// Product-surface caps (e.g. a separate app) are not modelled here.
		return claudeLimitUnattributed
	}
	scopeModel := scope.Get("model")
	if !scopeModel.IsObject() {
		return claudeLimitUnattributed
	}
	id := normalizeClaudeModelName(scopeModel.Get("id").String())
	name := normalizeClaudeModelName(scopeModel.Get("display_name").String())
	if id == "" && name == "" {
		return claudeLimitUnattributed
	}
	if normalizedModel != "" &&
		((id != "" && strings.Contains(normalizedModel, id)) || (name != "" && strings.Contains(normalizedModel, name))) {
		return claudeLimitThisModel
	}
	// Only a scope that names a known family is safely unrelated to a model
	// whose family is also known.
	scopeFamily := claudeModelFamily(id)
	if scopeFamily == "" {
		scopeFamily = claudeModelFamily(name)
	}
	if scopeFamily != "" && family != "" {
		return claudeLimitOtherModel
	}
	return claudeLimitUnattributed
}

// normalizeClaudeModelName lowercases and collapses separators so that
// display names such as "Fable 5.2" match model IDs such as claude-fable-5-2.
func normalizeClaudeModelName(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	dash := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
			continue
		}
		if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

func claudeModelFamily(normalized string) string {
	for _, family := range claudeKnownFamilies {
		if strings.Contains(normalized, family) {
			return family
		}
	}
	return ""
}

func validClaudeUsagePercent(value ojson.Result) bool {
	if value.Type != ojson.Number {
		return false
	}
	f := value.Float()
	return f >= 0 && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// ClaudeOverloadRetryAfter ignores subscription reset headers on 529 responses.
// Only an explicit Retry-After describes recovery from upstream overload.
func ClaudeOverloadRetryAfter(headers http.Header, now time.Time) *time.Duration {
	deadline, ok := parseRetryAfterHeader(getHeaderCaseInsensitive(headers, "Retry-After"), now)
	if !ok || !deadline.After(now) {
		return nil
	}
	retry := deadline.Sub(now)
	return &retry
}

// LogClaudeRateLimitHeaders records Anthropic's rate-limit headers for a
// rejected request so a cooldown decision can be audited later. These headers
// carry no credentials or content.
func LogClaudeRateLimitHeaders(ctx context.Context, status int, headers http.Header, model string) {
	if headers == nil {
		return
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "anthropic-ratelimit-") || lower == "retry-after" || lower == "x-should-retry" {
			keys = append(keys, lower)
		}
	}
	if len(keys) == 0 {
		return
	}
	sort.Strings(keys)
	fields := log.Fields{"upstream_status": status, "model": model}
	for _, key := range keys {
		fields[strings.TrimPrefix(key, "anthropic-ratelimit-")] = getHeaderCaseInsensitive(headers, key)
	}
	LogWithRequestID(ctx).WithFields(fields).Warn("Claude upstream rejection headers")
}
