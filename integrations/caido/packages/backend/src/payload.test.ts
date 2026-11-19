import { test } from "node:test";
import assert from "node:assert/strict";

import { base64, buildPayload, parseSettings, shouldForward, DEFAULT_ENDPOINT } from "./payload.ts";

test("base64 matches Node's encoder", () => {
  for (const s of ["", "a", "ab", "abc", "abcd", "hello world", "ÿ\u0000\u0010"]) {
    const bytes = new TextEncoder().encode(s);
    assert.equal(base64(bytes), Buffer.from(bytes).toString("base64"));
  }
});

test("only HTML and JS are forwarded", () => {
  assert.ok(shouldForward("/app.js?v=1", {}));
  assert.ok(shouldForward("/", { "Content-Type": ["text/html; charset=utf-8"] }));
  assert.ok(shouldForward("/x", { "content-type": ["application/javascript"] }));
  assert.ok(!shouldForward("/logo.png", { "Content-Type": ["image/png"] }));
  assert.ok(!shouldForward("/api/data", { "Content-Type": ["application/json"] }));
});

test("payload shape matches the jxscout-rs DTO", () => {
  const p = buildPayload("https://a.test/x.js", "GET", { Cookie: ["s=1"] }, 200, {}, new TextEncoder().encode("hi"));
  assert.deepEqual(p, {
    request: { url: "https://a.test/x.js", method: "GET", headers: { Cookie: ["s=1"] } },
    response: { status: 200, headers: {}, body_base64: "aGk=" },
  });
});

test("settings defaults and overrides", () => {
  assert.deepEqual(parseSettings(() => undefined), { endpoint: DEFAULT_ENDPOINT, token: undefined, inScopeOnly: true });
  const env: Record<string, string> = { JXSCOUT_ENDPOINT: "http://localhost:4444/ingest", JXSCOUT_TOKEN: "t", JXSCOUT_IN_SCOPE_ONLY: "false" };
  assert.deepEqual(parseSettings((n) => env[n]), { endpoint: "http://localhost:4444/ingest", token: "t", inScopeOnly: false });
});
