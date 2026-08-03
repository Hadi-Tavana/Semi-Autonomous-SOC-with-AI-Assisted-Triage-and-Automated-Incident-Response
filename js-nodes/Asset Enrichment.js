// ===== Asset Database (keep your full list here) =====
const assetDb = {
  "192.168.1.100": { hostname: "PDC", role: "Domain Controller", os: "Windows Server 2022", segment: "Network-A", priority: 5, internal: true },
  "192.168.1.120": { hostname: "WebServer", role: "IIS Web Server", os: "Windows Server 2022", segment: "Network-A", priority: 4, internal: true },
  "192.168.1.254": { hostname: "Firewall-A", role: "GW-A Internal", os: "OPNsense", segment: "Network-A", priority: 5, internal: true },
  "192.168.2.100": { hostname: "SecurityOnion", role: "SIEM", os: "Security Onion 2", segment: "Network-B", priority: 5, internal: true },
  "192.168.2.200": { hostname: "Velociraptor", role: "Incident Response", os: "Ubuntu 24.04", segment: "Network-B", priority: 4, internal: true },
  "192.168.2.250": { hostname: "SOAR-Stack", role: "n8n+TheHive", os: "Ubuntu 24.04", segment: "Network-B", priority: 5, internal: true },
  "192.168.2.254": { hostname: "Firewall-B", role: "GW-B Internal", os: "OPNsense", segment: "Network-B", priority: 5, internal: true },
  "172.16.206.14": { hostname: "Firewall-A-WAN", role: "WAN Interface", os: "OPNsense", segment: "University-External", priority: 5, internal: false },
  "172.16.218.12": { hostname: "Firewall-B-WAN", role: "WAN Interface", os: "OPNsense", segment: "University-External", priority: 5, internal: false }
};

const hostnameDb = {};
for (const ip in assetDb) {
  const asset = assetDb[ip];
  hostnameDb[asset.hostname.toLowerCase()] = { ...asset, ip };
}

// ===== Helpers =====
function detectSegment(ip) {
  if (!ip) return null;
  if (ip.startsWith("192.168.1.")) return "Network-A";
  if (ip.startsWith("192.168.2.")) return "Network-B";
  return null;
}

function externalAsset(ip) {
  return { hostname: "Unknown-External", ip, segment: "Internet", priority: 1, internal: false };
}

function internalUnknown(ip) {
  const segment = detectSegment(ip);
  if (!segment) return null;
  return { hostname: "Internal-Unknown", ip, segment, priority: 2, internal: true };
}

function resolveAsset(ip, hostnameFromArtifacts) {
  if (hostnameFromArtifacts) {
    const h = hostnameDb[hostnameFromArtifacts.toLowerCase()];
    if (h) return { ...h, ip: h.ip || ip };
  }
  if (ip && assetDb[ip]) return { ...assetDb[ip], ip };
  const internal = internalUnknown(ip);
  return internal || externalAsset(ip);
}

function extractHostname(artifacts) {
  if (!artifacts || !Array.isArray(artifacts)) return null;
  for (const a of artifacts) {
    if (a.dataType === "hostname" && a.data) return a.data;
  }
  return null;
}

// ===== Smarter Flow Classification =====
function classifyFlow(alert, src_asset, dst_asset) {
  const ruleName = (alert.rule?.name || "").toLowerCase();
  const mitre = alert.rule?.mitre || [];

  // 1. Explicit network-based indicators
  if (dst_asset && dst_asset.ip) {
    if (!src_asset.internal && dst_asset.internal) return "External Attack";
    if (src_asset.internal && !dst_asset.internal) return "Outbound (C2 likely)";
    if (src_asset.internal && dst_asset.internal) {
      if (src_asset.ip === dst_asset.ip || src_asset.hostname === dst_asset.hostname) 
        return "Single Host Activity";
      if (src_asset.segment !== dst_asset.segment) return "Cross-Segment Movement";
      return "Lateral Movement";
    }
  }

  // 2. Rule name / MITRE hints (very useful for your Elastic rules)
  if (ruleName.includes("c2") || ruleName.includes("command and control") || 
      ruleName.includes("caldera") || ruleName.includes("sandcat")) {
    return "Outbound C2 / Beaconing";
  }
  if (ruleName.includes("kerberoasting") || ruleName.includes("credential")) {
    return "Credential Access (Single Host)";
  }
  if (ruleName.includes("privilege escalation") || ruleName.includes("token impersonation")) {
    return "Privilege Escalation (Single Host)";
  }
  if (ruleName.includes("webshell") || ruleName.includes("iis worker") || ruleName.includes("payload drop")) {
    return "Web Shell / Execution (Single Host)";
  }
  if (ruleName.includes("discovery") || ruleName.includes("account discovery")) {
    return "Discovery (Single Host)";
  }
  if (ruleName.includes("admin account creation") || ruleName.includes("persistence")) {
    return "Persistence (Single Host)";
  }

  // 3. MITRE-based fallback
  const hasExecution = mitre.some(m => m.tactic?.id === "TA0002");
  const hasPersistence = mitre.some(m => m.tactic?.id === "TA0003");
  const hasC2 = mitre.some(m => m.tactic?.id === "TA0011");

  if (hasC2) return "Outbound C2 / Beaconing";
  if (hasExecution && hasPersistence) return "Execution + Persistence (Single Host)";
  if (hasExecution) return "Execution (Single Host)";

  // 4. Final safe fallback
  return src_asset.internal ? "Single Host Activity" : "External Activity";
}

// ===== Main Processing =====
const output = [];
for (const item of items) {
  const alert = item.json;

  const src_ip = alert.network?.src_ip || null;
  const dst_ip = alert.network?.dst_ip || null;
  const hostname = extractHostname(alert.artifacts);

  const src_asset = resolveAsset(src_ip, hostname);
  const dst_asset = dst_ip ? resolveAsset(dst_ip, null) : null;

  const asset_context = { src_asset };
  if (dst_asset) asset_context.dst_asset = dst_asset;

  const flow = classifyFlow(alert, src_asset, dst_asset);

  const soc_priority = Math.max(
    alert.rule?.severity || 1,
    src_asset?.priority || 1,
    (dst_asset?.priority || 1)
  );

  // Fix bucket_5m if broken
  if (alert.timestamps?.bucket_5m && typeof alert.timestamps.bucket_5m === "number") {
    const fixed = new Date(alert.timestamps.original);
    fixed.setSeconds(0, 0);
    alert.timestamps.bucket_5m = fixed.toISOString();
  }

  alert.asset_context = asset_context;
  alert.asset_flow = flow;
  alert.soc_priority = soc_priority;

  const dedupKey = [
    alert.rule?.name || "unknown",
    src_ip || "na",
    dst_ip || "na",
    src_asset?.hostname || "na",
    alert.timestamps?.bucket_5m || "na"
  ].join("|");

  alert.dedup_key = dedupKey;

  output.push({ json: alert });
}

return output;
