const output = [];

for (const item of items) {
  const alert = item.json;

  const rawTargets = alert.osint_targets || [];

  // --- helper: check private/internal IPs ---
  const isPrivateIP = (ip) => {
    if (!ip) return true;

    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.2') // covers 172.20–172.29
    );
  };

  // --- helper: validate OSINT target ---
  const isValidTarget = (t) => {
    if (!t || !t.value) return false;

    switch (t.type) {
      case 'ip':
        return !isPrivateIP(t.value);

      case 'domain':
        return !t.value.includes('windowsupdate.com');

      case 'url':
        return t.value.length > 5;

      case 'hash':
        return t.value.length >= 32;

      case 'command_line':
        return false;

      default:
        return false;
    }
  };

  // --- filter targets ---
  const filteredTargets = rawTargets.filter(isValidTarget);

  const hasOsint = filteredTargets.length > 0;

  // 🔴 IMPORTANT CHANGE: emit ONE ITEM PER TARGET
  if (hasOsint) {
    for (const t of filteredTargets) {
      output.push({
        json: {
          // 🔹 target (used by Dispatcher)
          type: t.type,
          value: t.value,

          // 🔹 keep alert context
          alert_id: alert.alert_id,
          title: alert.title,
          source: alert.source,
          severity: alert.severity,
          soc_priority: alert.soc_priority,

          // 🔹 keep original fields if needed downstream
          ...alert,

          // 🔹 control flags (still preserved)
          has_osint_targets: true,
          enrichment_status: "pending",
          osint_target_count: filteredTargets.length
        }
      });
    }
  } else {
    // 🔹 preserve alerts with NO OSINT targets (important for your IF node)
    output.push({
      json: {
        ...alert,
        osint_targets_filtered: [],
        has_osint_targets: false,
        enrichment_status: "skipped",
        osint_target_count: 0
      }
    });
  }
}

return output;
