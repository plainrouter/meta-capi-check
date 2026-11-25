import crypto from "node:crypto";

export const MUST_HASH_FIELDS = new Set([
  "em",
  "ph",
  "fn",
  "ln",
  "ge",
  "db",
  "ct",
  "st",
  "zp",
  "country",
  "external_id",
]);

export const DO_NOT_HASH_FIELDS = new Set([
  "fbp",
  "fbc",
  "client_ip_address",
  "client_user_agent",
  "subscription_id",
  "fb_login_id",
  "lead_id",
  "anon_id",
  "madid",
  "page_id",
  "page_scoped_user_id",
  "ctwa_clid",
  "ig_account_id",
]);

export const VALID_ACTION_SOURCES = new Set([
  "email",
  "website",
  "app",
  "phone_call",
  "chat",
  "physical_store",
  "system_generated",
  "business_messaging",
  "other",
]);

const SHA256_LOWER_RE = /^[a-f0-9]{64}$/;
const SHA256_ANY_CASE_RE = /^[a-fA-F0-9]{64}$/;
const PLACEHOLDER_VALUES = ["", "null", "undefined", "none", "n/a", "na", "-"];

export function sha256Hex(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

export const PLACEHOLDER_HASHES = new Map(
  PLACEHOLDER_VALUES.map((v) => [sha256Hex(v), v === "" ? '"" (empty string)' : `"${v}"`])
);

export function normalizeFieldValue(field, raw) {
  if (raw === null || raw === undefined) return undefined;
  const trimmed = String(raw).trim();
  if (!trimmed) return undefined;
  const lower = trimmed.toLowerCase();
  if (PLACEHOLDER_VALUES.includes(lower)) return undefined;

  switch (field) {
    case "em":
      return lower;
    case "ph": {
      const digits = trimmed.replace(/\D/g, "").replace(/^0+/, "");
      return digits || undefined;
    }
    case "fn":
    case "ln":
      return lower.replace(/[^a-z0-9\p{L}]/gu, "") || undefined;
    case "ct":
      return lower.replace(/[^a-z\p{L}]/gu, "") || undefined;
    case "st":
      return lower.replace(/[^a-z]/g, "").slice(0, 2) || undefined;
    case "zp": {
      const clean = lower.replace(/\s+/g, "");
      if (/^\d{5}-\d{4}$/.test(clean)) return clean.slice(0, 5);
      return clean || undefined;
    }
    case "country":
      return lower.replace(/[^a-z]/g, "").slice(0, 2) || undefined;
    case "ge": {
      if (lower === "f" || lower === "female") return "f";
      if (lower === "m" || lower === "male") return "m";
      return undefined;
    }
    case "db": {
      const digits = trimmed.replace(/\D/g, "");
      return digits.length === 8 ? digits : undefined;
    }
    case "external_id":
      return trimmed;
    default:
      return trimmed;
  }
}

function asArray(val) {
  return Array.isArray(val) ? val : [val];
}

function validateFbpOrFbc(kind, raw, eventIndex, issues) {
  const pathPrefix = `data[${eventIndex}].user_data.${kind}`;
  if (Array.isArray(raw)) {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_ARRAY`,
      path: pathPrefix,
      message: `${kind} must be a single string, not an array.`,
    });
    return;
  }
  if (typeof raw !== "string") {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_TYPE`,
      path: pathPrefix,
      message: `${kind} must be a string.`,
    });
    return;
  }
  const value = raw.trim();
  if (!value || PLACEHOLDER_VALUES.includes(value.toLowerCase())) {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_EMPTY`,
      path: pathPrefix,
      message: `Omit ${kind} when absent instead of sending an empty or placeholder value.`,
    });
    return;
  }
  if (SHA256_ANY_CASE_RE.test(value)) {
    issues.push({
      severity: "error",
      code: "UD_WRONGLY_HASHED",
      path: pathPrefix,
      message: `${kind} appears to be SHA-256 hashed. Meta requires ${kind} raw (never hashed).`,
    });
    return;
  }

  const parts = value.split(".");
  if (parts.length < 4 || parts[0] !== "fb") {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_FORMAT`,
      path: pathPrefix,
      message:
        kind === "fbc"
          ? `Invalid fbc format. Expected "fb.<subdomain_index>.<creation_time_ms>.<fbclid>", not a raw query parameter.`
          : `Invalid fbp format. Expected "fb.<subdomain_index>.<creation_time_ms>.<random_number>".`,
    });
    return;
  }

  const subIndex = Number(parts[1]);
  if (!Number.isInteger(subIndex) || subIndex < 0) {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_SUBDOMAIN_INDEX`,
      path: pathPrefix,
      message: `Invalid subdomain_index "${parts[1]}" in ${kind}. Expected an integer such as 1 (root domain) or 2 (subdomain).`,
    });
  }

  const ts = Number(parts[2]);
  if (!Number.isFinite(ts) || ts <= 0) {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_TIMESTAMP`,
      path: pathPrefix,
      message: `Invalid creation timestamp "${parts[2]}" in ${kind}. Expected 13-digit Unix milliseconds.`,
    });
  } else if (ts < 1e11) {
    issues.push({
      severity: "error",
      code: `${kind.toUpperCase()}_TIMESTAMP_SECONDS`,
      path: pathPrefix,
      message: `${kind} creation timestamp (${parts[2]}) looks like Unix seconds. Meta requires 13-digit Unix milliseconds inside ${kind}.`,
    });
  }

  if (kind === "fbc") {
    const fbclid = parts.slice(3).join(".");
    if (fbclid.length >= 12 && fbclid === fbclid.toLowerCase() && /[a-z]/.test(fbclid)) {
      issues.push({
        severity: "warning",
        code: "FBC_LOWERCASED_FBCLID",
        path: pathPrefix,
        message:
          "The fbclid suffix in fbc is all lowercase. Meta fbclid values are case-sensitive; check that .toLowerCase() was not applied to fbc.",
      });
    }
  }
}

export function validateCapiPayload(input, options = {}) {
  const nowSec = options.nowSec ?? Math.floor(Date.now() / 1000);
  const issues = [];

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {
      ok: false,
      eventCount: 0,
      errors: 1,
      warnings: 0,
      issues: [
        {
          severity: "error",
          code: "INVALID_ROOT",
          path: "$",
          message: 'Payload must be a JSON object with a "data" array (or a single event object).',
        },
      ],
    };
  }

  let events;
  if (Array.isArray(input.data)) {
    events = input.data;
  } else if (typeof input.event_name === "string") {
    events = [input];
    issues.push({
      severity: "warning",
      code: "SINGLE_EVENT_WRAPPED",
      path: "$",
      message: 'Top-level "data" array not found; validated as a single event object. Meta CAPI requires { "data": [ ... ] }.',
    });
  } else {
    return {
      ok: false,
      eventCount: 0,
      errors: 1,
      warnings: 0,
      issues: [
        {
          severity: "error",
          code: "MISSING_DATA_ARRAY",
          path: "data",
          message: 'Payload must include a non-empty "data" array of event objects.',
        },
      ],
    };
  }

  if (events.length === 0) {
    issues.push({
      severity: "error",
      code: "EMPTY_DATA_ARRAY",
      path: "data",
      message: '"data" array is empty.',
    });
  }

  events.forEach((ev, idx) => {
    const base = `data[${idx}]`;
    if (!ev || typeof ev !== "object" || Array.isArray(ev)) {
      issues.push({ severity: "error", code: "INVALID_EVENT", path: base, message: "Event must be a JSON object." });
      return;
    }

    if (typeof ev.test_event_code === "string" && ev.test_event_code.trim()) {
      issues.push({
        severity: "error",
        code: "NESTED_TEST_EVENT_CODE",
        path: `${base}.test_event_code`,
        message: "test_event_code must be a top-level field beside data[], not nested inside an event object.",
      });
    }

    if (typeof ev.event_name !== "string" || !ev.event_name.trim()) {
      issues.push({ severity: "error", code: "MISSING_EVENT_NAME", path: `${base}.event_name`, message: "event_name is required." });
    } else if (ev.event_name === "purchase" || ev.event_name === "lead" || ev.event_name === "pageview") {
      issues.push({
        severity: "warning",
        code: "EVENT_NAME_CASE",
        path: `${base}.event_name`,
        message: `event_name "${ev.event_name}" is lowercase. Meta standard event names and deduplication are case-sensitive (e.g. "Purchase", "Lead", "PageView").`,
      });
    }

    if (typeof ev.event_time !== "number" || !Number.isFinite(ev.event_time)) {
      issues.push({
        severity: "error",
        code: "INVALID_EVENT_TIME",
        path: `${base}.event_time`,
        message: "event_time must be a Unix timestamp in seconds.",
      });
    } else if (ev.event_time > 1e11) {
      issues.push({
        severity: "error",
        code: "EVENT_TIME_MILLISECONDS",
        path: `${base}.event_time`,
        message: `event_time (${ev.event_time}) appears to be in milliseconds. Meta CAPI requires Unix seconds (Math.floor(Date.now() / 1000)).`,
      });
    } else {
      const ageSec = nowSec - ev.event_time;
      if (ageSec > 7 * 86400) {
        issues.push({
          severity: "error",
          code: "EVENT_TIME_TOO_OLD",
          path: `${base}.event_time`,
          message: `event_time is older than 7 days (${Math.round(ageSec / 86400)} days old). Meta rejects events older than 7 days (subcode 2804019).`,
        });
      } else if (ageSec < -300) {
        issues.push({
          severity: "error",
          code: "EVENT_TIME_FUTURE",
          path: `${base}.event_time`,
          message: "event_time is more than 5 minutes in the future.",
        });
      }
    }

    if (typeof ev.action_source !== "string" || !VALID_ACTION_SOURCES.has(ev.action_source)) {
      issues.push({
        severity: "error",
        code: "INVALID_ACTION_SOURCE",
        path: `${base}.action_source`,
        message: `action_source must be one of: ${[...VALID_ACTION_SOURCES].join(", ")}.`,
      });
    }

    if (ev.action_source === "website" && (typeof ev.event_source_url !== "string" || !ev.event_source_url.startsWith("http"))) {
      issues.push({
        severity: "error",
        code: "MISSING_EVENT_SOURCE_URL",
        path: `${base}.event_source_url`,
        message: 'event_source_url (full http/https URL) is required when action_source is "website".',
      });
    }

    if (typeof ev.event_id !== "string" || !ev.event_id.trim()) {
      issues.push({
        severity: "warning",
        code: "MISSING_EVENT_ID",
        path: `${base}.event_id`,
        message: "event_id is missing. Provide a deterministic event_id shared with Meta Pixel to enable deduplication.",
      });
    }

    const ud = ev.user_data;
    if (!ud || typeof ud !== "object" || Array.isArray(ud)) {
      issues.push({
        severity: "error",
        code: "MISSING_USER_DATA",
        path: `${base}.user_data`,
        message: "user_data object is required (subcode 2804050 when match parameters are missing).",
      });
    } else {
      let validMatchKeys = 0;

      for (const [key, val] of Object.entries(ud)) {
        if (val === undefined || val === null) continue;
        if (key === "fbp" || key === "fbc") {
          const beforeErrs = issues.length;
          validateFbpOrFbc(key, val, idx, issues);
          if (issues.length === beforeErrs) validMatchKeys++;
          continue;
        }
        if (DO_NOT_HASH_FIELDS.has(key)) {
          const str = typeof val === "string" ? val.trim() : "";
          if (SHA256_ANY_CASE_RE.test(str)) {
            issues.push({
              severity: "error",
              code: "UD_WRONGLY_HASHED",
              path: `${base}.user_data.${key}`,
              message: `${key} appears to be SHA-256 hashed. Meta requires ${key} to be sent raw.`,
            });
          } else if (str) {
            validMatchKeys++;
          }
          continue;
        }
        if (MUST_HASH_FIELDS.has(key)) {
          for (const item of asArray(val)) {
            if (typeof item !== "string" || !item.trim()) {
              issues.push({
                severity: "error",
                code: "UD_EMPTY_VALUE",
                path: `${base}.user_data.${key}`,
                message: `Omit ${key} when empty instead of sending blank values.`,
              });
              continue;
            }
            const trimmed = item.trim();
            if (SHA256_LOWER_RE.test(trimmed)) {
              if (PLACEHOLDER_HASHES.has(trimmed)) {
                issues.push({
                  severity: "error",
                  code: "UD_HASHED_PLACEHOLDER",
                  path: `${base}.user_data.${key}`,
                  message: `${key} contains the SHA-256 hash of ${PLACEHOLDER_HASHES.get(trimmed)}. Omit unknown fields before hashing.`,
                });
              } else {
                validMatchKeys++;
              }
            } else if (SHA256_ANY_CASE_RE.test(trimmed)) {
              issues.push({
                severity: "error",
                code: "UD_UPPERCASE_HASH",
                path: `${base}.user_data.${key}`,
                message: `${key} SHA-256 hash must be lowercase hex.`,
              });
            } else {
              issues.push({
                severity: "error",
                code: "UD_UNHASHED_PII",
                path: `${base}.user_data.${key}`,
                message: `${key} must be normalized and SHA-256 hashed (64-char lowercase hex).`,
              });
            }
          }
        }
      }

      if (ev.action_source === "website") {
        if (!ud.client_ip_address || !ud.client_user_agent) {
          issues.push({
            severity: "warning",
            code: "WEBSITE_IP_UA_MISSING",
            path: `${base}.user_data`,
            message: 'Include raw client_ip_address and client_user_agent for action_source "website" to improve Event Match Quality.',
          });
        }
      }
      if (validMatchKeys === 0) {
        issues.push({
          severity: "error",
          code: "INSUFFICIENT_MATCH_KEYS",
          path: `${base}.user_data`,
          message: "No valid customer match keys detected in user_data (triggers Meta subcode 2804050).",
        });
      }
    }

    const cd = ev.custom_data;
    if (ev.event_name === "Purchase") {
      if (!cd || typeof cd !== "object") {
        issues.push({
          severity: "error",
          code: "PURCHASE_MISSING_CUSTOM_DATA",
          path: `${base}.custom_data`,
          message: "Purchase events require custom_data.value (number) and custom_data.currency (3-letter ISO-4217).",
        });
      } else {
        if (typeof cd.value !== "number" || !Number.isFinite(cd.value)) {
          issues.push({
            severity: "error",
            code: "INVALID_CUSTOM_VALUE",
            path: `${base}.custom_data.value`,
            message: `custom_data.value must be a plain number (e.g. 49.0), not "${cd.value}".`,
          });
        }
        if (typeof cd.currency !== "string" || !/^[A-Z]{3}$/.test(cd.currency)) {
          issues.push({
            severity: "error",
            code: "INVALID_CURRENCY",
            path: `${base}.custom_data.currency`,
            message: `custom_data.currency must be a 3-letter uppercase ISO-4217 code (e.g. "USD"), not "${cd.currency}".`,
          });
        }
      }
    } else if (cd && typeof cd === "object" && cd.value !== undefined && typeof cd.value !== "number") {
      issues.push({
        severity: "warning",
        code: "NON_NUMERIC_VALUE",
        path: `${base}.custom_data.value`,
        message: `custom_data.value should be a numeric value without currency symbols or commas (got "${cd.value}").`,
      });
    }
  });

  const errors = issues.filter((i) => i.severity === "error").length;
  const warnings = issues.filter((i) => i.severity === "warning").length;

  return {
    ok: errors === 0,
    eventCount: events.length,
    errors,
    warnings,
    issues,
  };
}

export function normalizeAndHashUserData(userData) {
  if (!userData || typeof userData !== "object") return {};
  const out = {};
  for (const [key, val] of Object.entries(userData)) {
    if (val === null || val === undefined) continue;
    if (DO_NOT_HASH_FIELDS.has(key)) {
      const s = typeof val === "string" ? val.trim() : "";
      if (s && !PLACEHOLDER_VALUES.includes(s.toLowerCase())) out[key] = s;
      continue;
    }
    if (MUST_HASH_FIELDS.has(key)) {
      const hashes = [];
      for (const item of asArray(val)) {
        if (typeof item === "string" && SHA256_LOWER_RE.test(item.trim())) {
          const h = item.trim();
          if (!PLACEHOLDER_HASHES.has(h)) hashes.push(h);
          continue;
        }
        const norm = normalizeFieldValue(key, item);
        if (norm) hashes.push(sha256Hex(norm));
      }
      if (hashes.length === 1) out[key] = hashes[0];
      else if (hashes.length > 1) out[key] = hashes;
      continue;
    }
    out[key] = val;
  }
  return out;
}
