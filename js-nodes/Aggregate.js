const grouped = {};

function normalizeValue(v) {
  if (v === undefined || v === null || v === "") return null;
  return String(v).trim();
}

for (const item of items) {
  const alert = item.json;
  const key = alert.dedup_key || "unknown";

  if (!alert.artifacts) alert.artifacts = [];

  // Clean artifacts without destroying original casing for readability
  const cleanedArtifacts = alert.artifacts
    .filter(o => o && o.dataType && o.data)
    .map(o => ({
      dataType: o.dataType,
      data: normalizeValue(o.data)   // only normalize for dedup purposes
    }));

  if (!grouped[key]) {
    grouped[key] = {
      ...alert,
      count: 1,
      artifacts: [...cleanedArtifacts],
      related_alerts: [alert.rule?.name].filter(Boolean),
      firstSeen: alert.timestamps?.original,
      lastSeen: alert.timestamps?.original,
      // New helpful fields for AI + TheHive
      asset_flow: alert.asset_flow,
      soc_priority: alert.soc_priority,
      primary_asset: alert.asset_context?.src_asset?.hostname || "Unknown",
      mitre_summary: alert.rule?.mitre?.[0]?.tactic?.name || null
    };
  } else {
    const g = grouped[key];

    g.count += 1;

    // Update time window
    if (alert.timestamps?.original) {
      if (!g.firstSeen || alert.timestamps.original < g.firstSeen)
        g.firstSeen = alert.timestamps.original;
      if (!g.lastSeen || alert.timestamps.original > g.lastSeen)
        g.lastSeen = alert.timestamps.original;
    }

    // Merge artifacts (deduplicated)
    const existing = new Set(g.artifacts.map(o => `${o.dataType}:${o.data}`));
    for (const obs of cleanedArtifacts) {
      const fingerprint = `${obs.dataType}:${obs.data}`;
      if (!existing.has(fingerprint)) {
        g.artifacts.push(obs);
        existing.add(fingerprint);
      }
    }

    // Merge related rule names
    if (alert.rule?.name && !g.related_alerts.includes(alert.rule.name)) {
      g.related_alerts.push(alert.rule.name);
    }

    // Keep the highest soc_priority
    if (alert.soc_priority > g.soc_priority) {
      g.soc_priority = alert.soc_priority;
    }

    // Keep the most "interesting" asset_flow if they differ
    if (alert.asset_flow && alert.asset_flow !== "Single Host Activity" && 
        g.asset_flow === "Single Host Activity") {
      g.asset_flow = alert.asset_flow;
    }
  }
}

// Final output
return Object.values(grouped).map(g => ({
  json: {
    ...g,
    related_alerts: [...new Set(g.related_alerts)],   // final dedup
    // Optional: add a short summary for the AI agent
    summary: `${g.count} alerts | ${g.primary_asset} | ${g.asset_flow} | ${g.rule?.name || 'Multiple rules'}`
  }
}));
