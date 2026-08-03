function safe(v, def = null) {
  return v !== undefined && v !== null ? v : def;
}

function pick(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null) return v;
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

function mapSeverity(sev) {
  if (!sev) return 1;
  const map = { low: 1, medium: 2, high: 3, critical: 4 };
  if (typeof sev === "number") return sev;
  return map[String(sev).toLowerCase()] ?? 1;
}

function mapType(type) {
  const map = {
    ip: "ip",
    port: "other",
    protocol: "other",
    process_name: "other",
    parent_process_name: "other",
    file_path: "other",        // ← Changed from "file"
    file_name: "other",        // ← Changed from "filename"
    command_line: "other",
    parent_command_line: "other",
    hash: "hash",
    url: "url",
    domain: "domain",
    user: "other",
    host: "hostname",
    user_agent: "user-agent",
    http_method: "other"
  };
  return map[type] || "other";
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
  push("process_name", ctx.process_name);
  push("parent_process_name", ctx.parent_process_name);
  push("file_path", ctx.process_path);
  push("file_name", ctx.process_file);
  push("command_line", ctx.process_cmd);
  push("parent_command_line", ctx.parent_process_cmd);
  push("hash", ctx.process_hash);
  push("filepath", ctx.file_path_full);
  push("url", ctx.url);
  push("domain", ctx.domain);
  push("user_agent", ctx.user_agent);
  push("user", ctx.username);
  push("host", ctx.host);

  return artifacts;
}

return items.map(item => {
  const j = item.json;

  const eventTime = pick(j["@timestamp"], j.event?.created, j.event?.ingested);
  const bucket_5m = bucket5m(eventTime);

  const ruleName = pick(
    j["kibana.alert.rule.name"],
    j.rule?.name,
    j.signal?.rule?.name,
    j.event?.action,
    "elastic_alert"
  );

  const severity = mapSeverity(
    pick(j["kibana.alert.severity"], j["kibana.alert.rule.severity"], j.event?.severity, j.signal?.rule?.severity)
  );

  // MITRE (unchanged — already perfect)
  const threat = pick(j["kibana.alert.rule.threat"], j["kibana.alert.rule.parameters"]?.threat, j.threat) || [];
  const mitre = threat.map(entry => ({
    tactic: entry.tactic ? { id: entry.tactic.id, name: entry.tactic.name } : null,
    techniques: (entry.technique || []).map(tech => ({
      id: tech.id,
      name: tech.name,
      subtechnique: (tech.subtechnique || []).map(st => ({ id: st.id, name: st.name }))
    }))
  })).filter(Boolean);

  // === ENHANCED extraction for threshold alerts + all common Elastic fields ===
  const src_ip = pick(j["source.ip"], j.source?.ip);
  const src_port = pick(j["source.port"], j.source?.port);
  const dst_ip = pick(j["destination.ip"], j.destination?.ip);
  const dst_port = pick(j["destination.port"], j.destination?.port);
  const protocol = pick(j.network?.transport, j.network?.protocol);

  const process_path = pick(j.process?.executable, j.winlog?.event_data?.Image);
  const process_file = process_path ? process_path.split("\\").pop() : null;
  const process_name = pick(j.process?.name, process_file);

  const process_cmd = pick(j.process?.command_line, j.winlog?.event_data?.CommandLine);

  const process_hash = pick(
    j.process?.hash?.sha256, j.process?.hash?.sha1, j.process?.hash?.md5,
    j.winlog?.event_data?.Hashes
  );

  const parent_process_path = pick(j.process?.parent?.executable, j.winlog?.event_data?.ParentImage);
  const parent_process_file = parent_process_path ? parent_process_path.split("\\").pop() : null;
  const parent_process_name = pick(j.process?.parent?.name, parent_process_file);
  const parent_process_cmd = pick(j.process?.parent?.command_line, j.winlog?.event_data?.ParentCommandLine);

  const file_path_full = pick(
    j.file?.path, j.winlog?.event_data?.TargetFilename,
    j.winlog?.event_data?.FileName, process_path
  );

  const url = pick(j.url?.full, j.http?.request?.referrer);
  const domain = pick(j.url?.domain, j.destination?.domain);
  const http_method = pick(j.http?.request?.method);
  const user_agent = pick(j.user_agent?.original);

  // === CRITICAL FIX for threshold alerts ===
  const username = pick(
    j.user?.name,
    j["user.name"],
    j.winlog?.event_data?.TargetUserName,
    j.winlog?.event_data?.User,
    j["kibana.alert.original_event"]?.user?.name
  );

  const host = pick(
    j.host?.hostname,
    j.host?.name,
    j["host.name"],
    j["kibana.alert.original_event"]?.host?.name,
    j.agent?.name
  );

  const artifacts = buildArtifacts({
    src_ip, dst_ip, process_name, process_path, process_file, process_cmd, process_hash,
    parent_process_name, parent_process_cmd,
    file_path_full,
    url, domain, http_method, user_agent,
    username, host
  });

  return {
    json: {
      id: pick(j["kibana.alert.uuid"], j._id),
      source: "elastic",
      rule: { name: ruleName, severity, mitre },
      network: { src_ip, src_port, dst_ip, dst_port, protocol },
      artifacts,
      timestamps: { original: eventTime, bucket_5m }
    }
  };
});
