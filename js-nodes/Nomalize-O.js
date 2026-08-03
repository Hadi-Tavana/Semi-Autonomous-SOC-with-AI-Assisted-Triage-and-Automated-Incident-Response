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
    url: "url",
    user_agent: "user-agent",
    http_method: "other",
    signature: "other"
  };
  return map[type] || "other";
}

function isIPv4(value) {
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(value);
}

function buildArtifacts(ctx) {
  const artifacts = [];
  const seen = new Set();

  function push(type, value) {
    if (!value) return;
    const v = String(value).trim();
    const key = `${type}:${v}`;
    if (seen.has(key)) return;
    seen.add(key);
    artifacts.push({ dataType: mapType(type), data: v });
  }

  push("ip", ctx.src_ip);
  push("ip", ctx.dst_ip);
  push("port", ctx.src_port);
  push("port", ctx.dst_port);
  push("protocol", ctx.protocol);
  push("url", ctx.url);           // XSS payload should land here
  push("user_agent", ctx.user_agent);
  push("http_method", ctx.http_method);
  if (ctx.hostname) {
    if (isIPv4(ctx.hostname)) {
      push("ip", ctx.hostname);       // correct classification
    } else {
        push("domain", ctx.hostname);
      }
    }
  push("signature", ctx.signature);

  return artifacts;
}

return items.map(item => {
  const j = item.json;

  // Robust parsing of the raw field
  let raw = {};
  try {
    raw = JSON.parse(j.raw || "{}");
  } catch (e) {
    // If parsing fails, try to clean escaped quotes
    try {
      const cleaned = j.raw.replace(/\\"/g, '"');
      raw = JSON.parse(cleaned);
    } catch (e2) {
      raw = {};
    }
  }

  const eventTime = pick(
    j.timestamp,
    raw.timestamp,
    j.received_at
  );

  const bucket_5m = bucket5m(eventTime);

  const ruleName = pick(
    j.signature,
    raw.alert?.signature,
    "OPNsense IDS Alert"
  );

  const severity = Number(pick(j.severity, raw.alert?.severity, 1));

  const src_ip = pick(j.src_ip, raw.src_ip);
  const src_port = pick(j.src_port, raw.src_port);
  const dst_ip = pick(j.dst_ip, raw.dest_ip, raw.destination?.ip);
  const dst_port = pick(j.dst_port, raw.dest_port, raw.destination?.port);
  const protocol = pick(j.proto, raw.proto);

  // === More robust HTTP extraction ===
  const httpObj = raw.http || raw.Http || {};
  let url = pick(
    httpObj.url,
    httpObj.full_url,
    httpObj.request?.url
  );

  // Fallback: reconstruct URL from hostname + url
  if (!url && httpObj.hostname) {
    const path = httpObj.url || httpObj.path || "";
    url = `http://${httpObj.hostname}${path.startsWith('/') ? path : '/' + path}`;
  }

  const user_agent = pick(httpObj.http_user_agent, httpObj.user_agent);
  const http_method = pick(httpObj.http_method, httpObj.method);
  const hostname = pick(httpObj.hostname);

  const artifacts = buildArtifacts({
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol,
    url,                    // ← This should now capture the XSS payload
    user_agent,
    http_method,
    hostname,
    signature: ruleName
  });

  return {
    json: {
      id: j.event_id || j.id,
      source: "opnsense",
      rule: {
        name: ruleName,
        severity: severity
      },
      network: {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol
      },
      artifacts,
      timestamps: {
        original: eventTime,
        bucket_5m
      },
      http: {
        url: url,
        method: http_method,
        user_agent: user_agent,
        hostname: hostname
      },
      category: pick(j.category, raw.alert?.category),
      signature: ruleName
    }
  };
});
