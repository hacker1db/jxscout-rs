// Pure helpers (no Caido imports) so they can be unit-tested with Node.

/** JSON accepted by jxscout-rs `POST /ingest` (see docs/SPEC.md R-11). */
export type IngestPayload = {
  request: {
    url: string;
    method: string;
    headers: Record<string, string[]>;
  };
  response: {
    status: number;
    headers: Record<string, string[]>;
    body_base64: string;
  };
};

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard base64. The Caido backend runtime has no `btoa`/`Buffer`. */
export function base64(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + "==";
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + "=";
  }
  return out;
}

function firstHeader(headers: Record<string, string[]>, name: string): string {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return (key !== undefined ? headers[key]?.[0] : undefined) ?? "";
}

/**
 * Only HTML and JavaScript are useful to jxscout-rs; skip images, fonts,
 * CSS, JSON, etc. so we don't flood the endpoint.
 */
export function shouldForward(path: string, responseHeaders: Record<string, string[]>): boolean {
  const ct = firstHeader(responseHeaders, "content-type").toLowerCase();
  if (ct.includes("html") || ct.includes("javascript") || ct.includes("ecmascript")) {
    return true;
  }
  const p = path.toLowerCase().split("?")[0] ?? "";
  return p.endsWith(".js") || p.endsWith(".mjs") || p.endsWith(".cjs");
}

export function buildPayload(
  url: string,
  method: string,
  requestHeaders: Record<string, string[]>,
  status: number,
  responseHeaders: Record<string, string[]>,
  body: Uint8Array,
): IngestPayload {
  return {
    request: { url, method, headers: requestHeaders },
    response: { status, headers: responseHeaders, body_base64: base64(body) },
  };
}

/** Settings read from Caido environment variables (Environment page). */
export type Settings = {
  endpoint: string;
  token: string | undefined;
  inScopeOnly: boolean;
};

export const DEFAULT_ENDPOINT = "http://127.0.0.1:3333/ingest";

export function parseSettings(get: (name: string) => string | undefined): Settings {
  const endpoint = get("JXSCOUT_ENDPOINT")?.trim() || DEFAULT_ENDPOINT;
  const token = get("JXSCOUT_TOKEN")?.trim() || undefined;
  const scope = (get("JXSCOUT_IN_SCOPE_ONLY") ?? "true").trim().toLowerCase();
  return { endpoint, token, inScopeOnly: !["false", "0", "no", "off"].includes(scope) };
}
