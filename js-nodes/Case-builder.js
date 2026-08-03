return items.map(item => {
  const alert = item.json;

  const count = alert.count || 1;
  const firstSeen = alert.firstSeen || alert.timestamps?.original;
  const lastSeen = alert.lastSeen || alert.timestamps?.original;

  // === Clean, Informative Title ===
  const title = [
    alert.rule?.name || "Security Alert",
    alert.primary_asset ? `on ${alert.primary_asset}` : "",
    alert.asset_flow ? `(${alert.asset_flow})` : ""
  ].filter(Boolean).join(" ");

  // === Rich Description for Analysts ===
  const description = `
Aggregated ${count} alert(s) in 5-minute window

• Asset          : ${alert.primary_asset || "Unknown"} (${alert.asset_context?.src_asset?.role || "Unknown role"})
• Flow           : ${alert.asset_flow || "Unknown"}
• SOC Priority   : ${alert.soc_priority || alert.rule?.severity || 3}
• MITRE Summary  : ${alert.mitre_summary || "None"}
• First seen     : ${firstSeen || "N/A"}
• Last seen      : ${lastSeen || "N/A"}
`.trim();

  // === Analyst Summary - Short & High-Value for AI Agent ===
  const analyst_summary = `
${count} alerts on ${alert.primary_asset || "Unknown asset"} (${alert.asset_context?.src_asset?.role || "Unknown"}).

Type: ${alert.asset_flow || "Unknown"}
MITRE: ${alert.mitre_summary || "None"}
Priority: ${alert.soc_priority || alert.rule?.severity || 3}

Time window: ${firstSeen ? new Date(firstSeen).toISOString() : "N/A"} → ${lastSeen ? new Date(lastSeen).toISOString() : "N/A"}
`.trim();

  // === Safe Artifacts for TheHive ===
  const safeArtifacts = (alert.artifacts || []).map(obs => {
    let dataType = obs.dataType || "other";
    let data = String(obs.data || "").trim();

    if (["filepath", "file_path", "file", "filename"].includes(dataType)) {
      dataType = "file";
      data = data.split(/[\\/]/).pop() || data;   // Only filename
    }

    if (dataType === "command_line") {
      dataType = "other";
    }

    return { dataType, data };
  });

  // === Rich Custom Fields - Optimized for AI Agent ===
  const customFields = {
    soc_priority: alert.soc_priority || alert.rule?.severity || 3,
    asset_flow: alert.asset_flow || "Unknown",
    primary_asset: alert.primary_asset || "Unknown",
    primary_hostname: alert.asset_context?.src_asset?.hostname || "Unknown",
    primary_role: alert.asset_context?.src_asset?.role || "Unknown",
    primary_os: alert.asset_context?.src_asset?.os || "Unknown",
    mitre_summary: alert.mitre_summary || "None",
    detection_source: alert.source || "unknown",
    alert_count: count,
    dedup_key: alert.dedup_key || "none",
    full_file_paths: (alert.artifacts || [])
      .filter(a => ["filepath", "file_path", "file"].includes(a.dataType))
      .map(a => a.data)
      .join(" | "),
    full_command_lines: (alert.artifacts || [])
      .filter(a => a.dataType === "command_line")
      .map(a => a.data)
      .join(" | ")
  };

  return {
    json: {
      type: "external",
      source: "n8n",
      sourceRef: alert.dedup_key 
        ? alert.dedup_key.toLowerCase().replace(/[^a-z0-9]/g, "_").slice(0, 100)
        : `alert_${Date.now()}`,

      title: title,
      description: description,

      severity: alert.soc_priority || alert.rule?.severity || 3,
      date: firstSeen ? new Date(firstSeen).getTime() : Date.now(),

      tlp: 2,
      pap: 2,

      tags: [
        "n8n",
        alert.source || "elastic",
        alert.asset_flow ? alert.asset_flow.toLowerCase().replace(/\s+/g, "-") : "single-host"
      ].filter(Boolean),

      artifacts: safeArtifacts,

      // All context the AI agent needs
      customFields: customFields,

      // Dedicated short summary field for the AI
      analyst_summary: analyst_summary
    }
  };
});
