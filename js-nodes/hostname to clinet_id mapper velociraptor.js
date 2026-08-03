const mapping = {
  webserver: "C.33aec7bb21619463",
  pdc: "C.669de98b6f0d50d2",
};

const seen = new Set();

const result = items
  .map((item) => {
    const data = item.json;

    const hostname =
      data.alert?.src_asset?.toLowerCase() ||
      data.src_asset?.toLowerCase();

    const client_id = mapping[hostname];

    if (!client_id) return null;

    return { hostname, client_id };
  })
  .filter(Boolean)
  .filter((item) => {
    if (seen.has(item.client_id)) return false;
    seen.add(item.client_id);
    return true;
  })
  .map((item) => ({ json: item }));

return result;
