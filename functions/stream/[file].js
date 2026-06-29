





export async function onRequest(context) {
  const { env, params, request } = context;
  const file = params.file;
  if (!env.EDITS) return new Response("Not configured", { status: 503 });

  const head = await env.EDITS.head(file);
  if (!head) return new Response("Not found", { status: 404 });
  const size = head.size;

  const baseHeaders = () => {
    const h = new Headers();
    head.writeHttpMetadata(h);
    if (!h.get("content-type")) h.set("content-type", "video/mp4");
    h.set("accept-ranges", "bytes");
    h.set("etag", head.httpEtag);
    h.set("cache-control", "private, max-age=3600");
    return h;
  };

  if (request.method === "HEAD") {
    const h = baseHeaders();
    h.set("content-length", String(size));
    return new Response(null, { status: 200, headers: h });
  }

  const range = request.headers.get("range");
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range);
    let start = m && m[1] ? parseInt(m[1], 10) : 0;
    let end = m && m[2] ? parseInt(m[2], 10) : size - 1;
    if (isNaN(start) || start < 0) start = 0;
    if (isNaN(end) || end >= size) end = size - 1;
    if (start > end) {
      return new Response("Range Not Satisfiable", { status: 416, headers: { "content-range": `bytes */${size}` } });
    }
    const obj = await env.EDITS.get(file, { range: { offset: start, length: end - start + 1 } });
    if (!obj || !obj.body) return new Response("Not found", { status: 404 });
    const h = baseHeaders();
    h.set("content-range", `bytes ${start}-${end}/${size}`);
    h.set("content-length", String(end - start + 1));
    return new Response(obj.body, { status: 206, headers: h });
  }

  const obj = await env.EDITS.get(file);
  if (!obj || !obj.body) return new Response("Not found", { status: 404 });
  const h = baseHeaders();
  h.set("content-length", String(size));
  return new Response(obj.body, { status: 200, headers: h });
}
