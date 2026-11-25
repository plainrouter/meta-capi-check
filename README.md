# meta-capi-check

Zero-dependency local CLI and Node.js library that catches Meta Conversions API (CAPI) payload bugs before they hit the wire, including the silent mistakes where Meta returns `HTTP 200 OK` while quietly breaking matching or deduplication.

Runs **100% locally** using Node's built-in `node:crypto` with zero outbound network requests.

## Quick Start

Validate a JSON payload file:

```bash
npx meta-capi-check payload.json
```

Validate from stdin (for CI pipelines or local test harnesses):

```bash
cat payload.json | npx meta-capi-check - --json
```

Preview Meta-compliant normalized and SHA-256 hashed `user_data` locally:

```bash
npx meta-capi-check payload.json --normalize
```

## What It Catches

- **Must-hash vs. do-not-hash mixups:** Flags unhashed PII (`em`, `ph`, `fn`, `ln`, `ge`, `db`, `ct`, `st`, `zp`, `country`, `external_id`), uppercase hex digests, and accidentally SHA-256 hashed browser/network keys (`fbp`, `fbc`, `client_ip_address`, `client_user_agent`, and 9 other Meta do-not-hash fields).
- **Hashed placeholders:** Detects SHA-256 hashes of `""`, `"null"`, `"undefined"`, `"none"`, and `"n/a"`.
- **`fbp` and `fbc` format bugs:** Checks `fb.<subdomain_index>.<creation_time_ms>.<id/fbclid>`, catches Unix seconds instead of milliseconds in segment 3, catches raw `?fbclid=...` values, and warns on lowercased `fbclid` suffixes.
- **`event_time` bugs:** Catches JavaScript millisecond timestamps (`Date.now()`), events older than 7 days (Meta subcode `2804019`), and future clock skew.
- **Test Events & deduplication bugs:** Flags `test_event_code` nested inside `data[]`, lowercase standard event names (`purchase` vs `Purchase`), and missing `event_id`.
- **Revenue formatting bugs:** Catches formatted currency strings (`"$49.00"`) and non-ISO-4217 currency codes.

## Programmatic Usage

```js
import { validateCapiPayload, normalizeAndHashUserData } from "meta-capi-check";

const result = validateCapiPayload(payload);
if (!result.ok) {
  console.error(result.issues);
}

const safeUserData = normalizeAndHashUserData({
  em: "Buyer@Example.com",
  ph: "+1 (415) 555-0199",
  fbp: "fb.1.1732469000000.1834267592",
});
```

## Related Browser Tool & Reference Guides

Maintained by [Plainrouter](https://plainrouter.com):

- Browser-local validator (zero install, Web Crypto): [plainrouter.com/tools/meta-capi-validator](https://plainrouter.com/tools/meta-capi-validator)
- Error code lookup (`100`, `190`, `2635`, `2804050`): [plainrouter.com/library/meta-capi-http-400-error-codes](https://plainrouter.com/library/meta-capi-http-400-error-codes)
- Cookie & click-ID rules (`_fbp`, `_fbc`, `fbclid`): [plainrouter.com/library/fbp-fbc](https://plainrouter.com/library/fbp-fbc)

## License

MIT
