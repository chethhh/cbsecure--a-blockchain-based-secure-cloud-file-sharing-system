const API_ORIGIN = "https://cb-secure-api.chethh1.workers.dev";

export async function onRequest({ request }) {
  const incomingUrl = new URL(request.url);
  const upstreamUrl = new URL(incomingUrl.pathname + incomingUrl.search, API_ORIGIN);
  const upstreamRequest = new Request(upstreamUrl, request);

  // Browser requests are same-origin at Pages. Let the API handle them without
  // applying a cross-origin policy for the Pages hostname.
  upstreamRequest.headers.delete("origin");

  const upstreamResponse = await fetch(upstreamRequest);
  const headers = new Headers(upstreamResponse.headers);
  headers.set("Cache-Control", "private, no-store");

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers,
  });
}
