# Claude usage checks and cooldown recovery

The hub checks Claude OAuth subscription usage on failure, without periodic
usage polling. Successful requests do not fetch usage.

- Before applying a long or credential-wide upstream 429 cooldown, compare it
  with usage. Confirmed available usage produces a model-only rate backoff;
  exhausted or unknown usage preserves the upstream cooldown.
- On upstream 529, check usage for diagnosis and cache reuse. Available quota
  does not disprove overload: retain the upstream error, Retry-After, and normal
  failover policy. Fast requests retain their original direct error response.
- When local selection would reject a request because credentials are cooling,
  check eligible credentials with quota cooldowns lasting more than 30 seconds.
  Confirmed recovery clears the stale cooldown and retries selection once for
  the same request. Credentials already attempted by that request are excluded.

Usage snapshots, including lookup failures, are cached for one minute and shared
across models and simultaneous callers. Each lookup has a three-second budget;
no more than three usage lookups run concurrently. Recovery also limits itself
to three credentials per request, three concurrent checks across requests, and
one check per credential per minute. Both caches hold at most 256 entries.
The first recovered credential lets selection resume without waiting for slower
checks. Canceling one request does not cancel a lookup shared by other callers.

Automatic recovery requires available usage for every model whose quota state
would be cleared. Unknown results, API keys, custom upstreams, disabled or
unauthorized credentials, and non-quota restrictions do not qualify. This also
includes independent model restrictions hidden under a credential quota. Ordinary
rate backoff and overload backoff are never removed by a quota recovery check.
A credential replacement or a newer result arriving during a lookup invalidates
the attempted reset. Existing pinning, eligibility, aliases, and session routing
remain authoritative; Home and plugin schedulers are not overridden.

The explicit `RecoverQuotaCooldowns` SDK method uses the same limits and returns
as soon as a credential recovers. Other checks already in flight can complete.
