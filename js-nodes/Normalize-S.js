function pick(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return null;
}

function bucket5m(ts) {
  if (!ts) return null;
  const d = new Date(ts);
  if (isNaN(d.getTime())) return null;

  const floored = Math.floor(d.getMinutes() / 5) * 5;
  d.setMinutes(floored);
  d.setSeconds(0);
  d.setMilliseconds(0);

  return d.toISOString();
}

function mapType(type) {

  const map = {
    ip: "ip",
    port: "other",
    protocol: "other",
    domain: "domain",
    community_id: "other"
  };

  return map[type] || "other";
}

function isValidDomain(d) {
  if (!d) return false;

  const v = String(d).trim().toLowerCase();

  if (v.startsWith(".")) return false;
  if (v === "get") return false;

  return true;
}

function buildArtifacts(ctx) {

  const artifacts = [];
  const seen = new Set();

  function push(type, value) {

    if (!value) return;

    const v = String(value).trim();

    if (!v) return;

    const key = `${type}:${v}`;

    if (seen.has(key)) return;
    seen.add(key);

    artifacts.push({
      dataType: mapType(type),
      data: v
    });
  }

  // useful artifacts
  push("ip", ctx.src_ip);
  push("ip", ctx.dst_ip);

  if (isValidDomain(ctx.domain)) {
    push("domain", ctx.domain);
  }

  return artifacts;
}

const normalized = [];

for (const item of $input.all()) {

  const src = item.json;

  const baseTs = pick(
    src["@timestamp"],
    src.event_timestamp_utc
  );

  const id = pick(
    src.log?.id?.uid,
    src.rule?.uuid,
    src.network?.community_id
  );

  const rule = {
    name: pick(src.rule?.name),
    severity: pick(src.event?.severity, src.rule?.severity)
  };

  const network = {
    src_ip: pick(src.source?.ip),
    src_port: pick(src.source?.port),
    dst_ip: pick(src.destination?.ip),
    dst_port: pick(src.destination?.port),
    protocol: pick(src.network?.transport),
    community_id: pick(src.network?.community_id)
  };

  const dns_query = pick(src.dns?.query_name);

  const artifacts = buildArtifacts({
    src_ip: network.src_ip,
    src_port: network.src_port,
    dst_ip: network.dst_ip,
    dst_port: network.dst_port,
    protocol: network.protocol,
    domain: dns_query,
    community_id: network.community_id
  });

  normalized.push({
    id,
    source: "suricata",
    rule,
    network,
    artifacts,
    timestamps: {
      original: baseTs,
      bucket_5m: bucket5m(baseTs)
    }
  });

}

return normalized.map(n => ({ json: n }));
