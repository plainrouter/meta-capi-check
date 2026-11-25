import test from "node:test";
import assert from "node:assert/strict";
import { validateCapiPayload, normalizeAndHashUserData, sha256Hex } from "../src/validator.mjs";

const NOW = 1764000000;

test("valid Purchase payload passes with zero errors and warnings", () => {
  const payload = {
    data: [
      {
        event_name: "Purchase",
        event_time: NOW - 60,
        action_source: "website",
        event_source_url: "https://example.com/checkout/thank-you",
        event_id: "order_1042_purchase",
        user_data: {
          em: [sha256Hex("buyer@example.com")],
          fbp: `fb.1.${(NOW - 300) * 1000}.1834267592`,
          fbc: `fb.1.${(NOW - 300) * 1000}.IwAR2xY9aBcDeFgHiJkLmNoPqRs`,
          client_ip_address: "203.0.113.42",
          client_user_agent: "Mozilla/5.0",
        },
        custom_data: { value: 49.5, currency: "USD" },
      },
    ],
  };

  const res = validateCapiPayload(payload, { nowSec: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.errors, 0);
  assert.equal(res.warnings, 0);
});

test("catches silent HTTP 200 bugs: hashed fbp, ms event_time, hashed empty string, formatted currency, nested test_event_code", () => {
  const payload = {
    data: [
      {
        event_name: "Purchase",
        event_time: NOW * 1000,
        action_source: "website",
        test_event_code: "TEST12345",
        user_data: {
          em: sha256Hex(""),
          ph: sha256Hex("null"),
          fbp: sha256Hex("fb.1.1732469000000.1834267592"),
          fbc: "fb.1.1732469000.iwar2lowercasedfbclidvalue",
        },
        custom_data: { value: "$49.00", currency: "usd" },
      },
    ],
  };

  const res = validateCapiPayload(payload, { nowSec: NOW });
  assert.equal(res.ok, false);
  const codes = new Set(res.issues.map((i) => i.code));
  assert.ok(codes.has("NESTED_TEST_EVENT_CODE"));
  assert.ok(codes.has("EVENT_TIME_MILLISECONDS"));
  assert.ok(codes.has("UD_HASHED_PLACEHOLDER"));
  assert.ok(codes.has("UD_WRONGLY_HASHED"));
  assert.ok(codes.has("FBC_TIMESTAMP_SECONDS"));
  assert.ok(codes.has("FBC_LOWERCASED_FBCLID"));
  assert.ok(codes.has("INVALID_CUSTOM_VALUE"));
  assert.ok(codes.has("INVALID_CURRENCY"));
});

test("normalizeAndHashUserData hashes PII, strips placeholders, and keeps do-not-hash keys raw", () => {
  const out = normalizeAndHashUserData({
    em: "  Jane.Doe@Example.COM ",
    ph: "+1 (415) 555-0199",
    ct: "San Francisco",
    zp: "94107-1234",
    ge: "Female",
    db: "1990-05-14",
    fn: "null",
    fbp: "fb.1.1732469000000.1834267592",
    fbc: "fb.1.1732469000000.IwAR2CaseSensitive",
  });

  assert.equal(out.em, sha256Hex("jane.doe@example.com"));
  assert.equal(out.ph, sha256Hex("14155550199"));
  assert.equal(out.ct, sha256Hex("sanfrancisco"));
  assert.equal(out.zp, sha256Hex("94107"));
  assert.equal(out.ge, sha256Hex("f"));
  assert.equal(out.db, sha256Hex("19900514"));
  assert.equal(out.fn, undefined);
  assert.equal(out.fbp, "fb.1.1732469000000.1834267592");
  assert.equal(out.fbc, "fb.1.1732469000000.IwAR2CaseSensitive");
});
