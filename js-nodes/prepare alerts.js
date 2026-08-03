// -------------------- CUSTOM FIELDS --------------------
function cfMap(customFields = {}) {
  const out = {};

  for (const [key, val] of Object.entries(customFields)) {
    if (!val) continue;

    const extracted =
      val.string ??
      val.integer ??
      val.boolean ??
      val.float ??
      val.date ??
      null;

    out[key] = extracted;
  }

  return out;
}

// -------------------- DESCRIPTION PARSING --------------------
function extractFirstLastSeen(description = "") {
  const firstMatch = description.match(/First seen\s*:\s*([^\n]+)/i);
  const lastMatch  = description.match(/Last seen\s*:\s*([^\n]+)/i);

  return {
    first_seen: firstMatch ? firstMatch[1].trim() : null,
    last_seen: lastMatch ? lastMatch[1].trim() : null
  };
}

// -------------------- NORMALIZERS --------------------
function normalizeBool(v) {
  if (v === true || v === false) return v;
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  if (["true", "yes", "1"].includes(s)) return true;
  if (["false", "no", "0"].includes(s)) return false;
  return null;
}

function normalizeHostname(v) {
  if (!v || typeof v !== "string") return null;
  return v.trim().toLowerCase();
}

function normalizeIP(v) {
  if (!v || typeof v !== "string") return null;
  return v.trim();
}

// -------------------- ARTIFACT EXTRACTION --------------------
function extractArtifactsSmart(artifacts = []) {
  const out = {
    src_ip: null,
    dst_ip: null,
    domain: null,
    urls: [],
    user_agent: null,
    process_names: [],
    command_lines: [],
    file_paths: [],
    hashes: [],
    ports: [],
    raw: []
  };

  for (const a of artifacts) {
    if (!a?.data || !a?.dataType) continue;

    const v = String(a.data).trim();
    const t = a.dataType;

    out.raw.push({ type: t, value: v });

    if (t === "ip") {
      if (!out.src_ip) out.src_ip = v;
      else if (!out.dst_ip) out.dst_ip = v;
      continue;
    }

    if (t === "domain") {
      out.domain = v;
      continue;
    }

    if (t === "url") {
      out.urls.push(v);
      continue;
    }

    if (t === "user-agent") {
      out.user_agent = v;
      continue;
    }

    if (t === "hash") {
      out.hashes.push(v);
      continue;
    }

    if (t === "other") {
      const lower = v.toLowerCase();

      if (lower.endsWith(".exe")) {
        out.process_names.push(v);
      }

      if (v.includes(" ") && (v.includes(".exe") || v.includes("-"))) {
        out.command_lines.push(v);
      }

      if (v.includes("\\") || v.includes("/")) {
        out.file_paths.push(v);
      }

      if (/^\d{2,5}$/.test(v)) {
        out.ports.push(v);
      }
    }
  }

  return out;
}

// -------------------- CLASSIFICATION --------------------
function classifyAlert(a) {
  const title = (a.title || "").toLowerCase();
  const source = (a.source || "").toLowerCase();
  const role = `${a.src_role || ""} ${a.dst_role || ""}`.toLowerCase();

  if (
    title.includes("powershell") ||
    title.includes("encodedcommand") ||
    title.includes("iex")
  ) {
    return {
      alert_type: "powershell_execution",
      playbook: "windows_powershell_investigation",
      default_time_window_minutes: 5,
      elastic_targets: ["endpoint_process", "powershell", "winlogbeat"],
      event_focus: ["process", "network", "dns"],
      max_events: 20
    };
  }

  if (
    title.includes("file") ||
    title.includes("process") ||
    title.includes("webshell")
  ) {
    if (role.includes("iis") || role.includes("web server")) {
      return {
        alert_type: "web_file_or_process_activity",
        playbook: "iis_webshell_or_process_investigation",
        default_time_window_minutes: 10,
        elastic_targets: ["endpoint_process", "endpoint_file", "iis"],
        event_focus: ["process", "file", "network"],
        max_events: 20
      };
    }

    return {
      alert_type: "windows_file_or_process_activity",
      playbook: "windows_file_process_investigation",
      default_time_window_minutes: 5,
      elastic_targets: ["endpoint_process", "endpoint_file"],
      event_focus: ["process", "file"],
      max_events: 20
    };
  }

  if (
    title.includes("scan") ||
    title.includes("nmap") ||
    source.includes("opnsense")
  ) {
    return {
      alert_type: "network_scan_or_recon",
      playbook: "network_scan_investigation",
      default_time_window_minutes: 3,
      elastic_targets: ["suricata", "firewall"],
      event_focus: ["network"],
      max_events: 30
    };
  }

  if (
    title.includes("web") ||
    title.includes("http")
  ) {
    return {
      alert_type: "web_activity",
      playbook: "iis_web_investigation",
      default_time_window_minutes: 10,
      elastic_targets: ["iis"],
      event_focus: ["web", "network"],
      max_events: 20
    };
  }

  return {
    alert_type: "generic_security_alert",
    playbook: "generic_investigation",
    default_time_window_minutes: 5,
    elastic_targets: ["endpoint_process", "suricata"],
    event_focus: ["process", "network"],
    max_events: 15
  };
}

// -------------------- OSINT TARGETS --------------------
function buildOsintTargets(a) {
  const targets = [];

  if (a.src_ip) targets.push({ type: "ip", value: a.src_ip });
  if (a.dst_ip) targets.push({ type: "ip", value: a.dst_ip });

  if (a.domain) targets.push({ type: "domain", value: a.domain });

  for (const u of a.urls || []) {
    targets.push({ type: "url", value: u });
  }

  for (const h of a.hashes || []) {
    targets.push({ type: "hash", value: h });
  }

  for (const c of a.command_lines || []) {
    if (
      c.toLowerCase().includes("http") ||
      c.toLowerCase().includes("powershell")
    ) {
      targets.push({ type: "command_line", value: c });
    }
  }

  return targets;
}

// -------------------- SUMMARY --------------------
function buildSummary(a) {
  return [
    `${a.alert_type} from ${a.source}`,
    a.src_ip && a.dst_ip ? `${a.src_ip} → ${a.dst_ip}` : null,
    a.process_names?.length ? `proc: ${a.process_names.slice(0,2).join(",")}` : null,
    a.urls?.length ? `url: ${a.urls[0]}` : null,
    a.hashes?.length ? `hash: ${a.hashes[0].slice(0,12)}...` : null,
    `priority=${a.soc_priority ?? "n/a"}`
  ].filter(Boolean).join(" | ");
}

// -------------------- MAIN --------------------
return items.map(item => {
  const j = item.json;

  const cf = cfMap(j.customFields || {});
  const seen = extractFirstLastSeen(j.description || "");
  const artifacts = extractArtifactsSmart(j.artifacts || []);

  const cleaned = {
    alert_id: j._id || null,
    title: j.title || null,
    source: cf.detection_source || j.source || null,
    severity: j.severity ?? null,
    date: j.date || null,

    alert_count: cf.alert_count ?? null,
    asset_flow: cf.asset_flow || null,

    src_ip: normalizeIP(cf.src_ip || artifacts.src_ip),
    dst_ip: normalizeIP(cf.dst_ip || artifacts.dst_ip),

    src_asset: normalizeHostname(cf.primary_asset || null),
    src_role: cf.primary_role || null,
    src_os: cf.primary_os || null,

    soc_priority: cf.soc_priority ?? null,

    domain: artifacts.domain,
    urls: artifacts.urls,
    user_agent: artifacts.user_agent,

    process_names: artifacts.process_names,
    command_lines: artifacts.command_lines,
    file_paths: artifacts.file_paths,
    hashes: artifacts.hashes,
    ports: artifacts.ports,

    first_seen: seen.first_seen,
    last_seen: seen.last_seen
  };

  const classification = classifyAlert(cleaned);

  Object.assign(cleaned, classification);

  cleaned.osint_targets = buildOsintTargets(cleaned);

  cleaned.summary_for_ai = buildSummary(cleaned);

  return { json: cleaned };
});
