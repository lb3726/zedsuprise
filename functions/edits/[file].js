


export async function onRequest(context) {
  const { env, params } = context;
  const file = params.file;
  if (!env.EDITS) return new Response("Downloads not configured", { status: 503 });
  const obj = await env.EDITS.get(file);
  if (!obj || !obj.body) return new Response("Not found", { status: 404 });

  const h = new Headers();
  obj.writeHttpMetadata(h);
  h.set("etag", obj.httpEtag);
  h.set("cache-control", "private, no-store");

  const names = {
    "cassidy-trailer.mp4": "Clint Cassidy - Trailer.mp4",
    "in-the-end.mp4": "HEYIM31 - In The End.mp4",
  };
  const nice = names[file] || file;
  h.set("Content-Disposition", `attachment; filename="${nice}"`);
  return new Response(obj.body, { headers: h });
}
