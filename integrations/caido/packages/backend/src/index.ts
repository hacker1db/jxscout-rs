// jxscout-rs Caido backend plugin.
//
// For every intercepted response that is in scope (by default) and looks
// like HTML or JavaScript, POST the request/response pair to the
// jxscout-rs ingest endpoint. Configure it with Caido environment
// variables (Environment page → Global):
//
//   JXSCOUT_ENDPOINT       default http://127.0.0.1:3333/ingest
//   JXSCOUT_TOKEN          the token printed by `jxscout-rs serve`
//   JXSCOUT_IN_SCOPE_ONLY  "true" (default) or "false"
import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";
import { Blob, Request as FetchRequest, fetch } from "caido:http";

import { buildPayload, parseSettings, shouldForward } from "./payload.ts";

async function forward(sdk: SDK, request: Request, response: Response): Promise<void> {
  const settings = parseSettings((name) => sdk.env.getVar(name));
  if (settings.inScopeOnly && !sdk.requests.inScope(request)) {
    return;
  }
  const responseHeaders = response.getHeaders();
  if (!shouldForward(request.getPath(), responseHeaders)) {
    return;
  }
  const body = response.getBody()?.toRaw() ?? new Uint8Array();
  const payload = buildPayload(
    request.getUrl(),
    request.getMethod(),
    request.getHeaders(),
    response.getCode(),
    responseHeaders,
    body,
  );
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (settings.token !== undefined) {
    headers["Authorization"] = `Bearer ${settings.token}`;
  }
  try {
    const res = await fetch(
      new FetchRequest(settings.endpoint, {
        method: "POST",
        headers,
        body: new Blob([JSON.stringify(payload)]),
      }),
    );
    if (res.status >= 300) {
      sdk.console.warn(`jxscout-rs: ingest returned HTTP ${res.status} for ${request.getUrl()}`);
    }
  } catch (e) {
    sdk.console.error(`jxscout-rs: could not reach ${settings.endpoint}: ${String(e)}`);
  }
}

export function init(sdk: SDK) {
  sdk.events.onInterceptResponse(async (sdk, request, response) => {
    await forward(sdk, request, response);
  });
  sdk.console.log("jxscout-rs: forwarding in-scope HTML/JS responses");
}
