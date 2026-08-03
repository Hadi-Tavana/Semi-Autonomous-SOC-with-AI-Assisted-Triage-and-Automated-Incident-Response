const FIVE_MIN = 5 * 60 * 1000;

function safe(v) {
  if (v === undefined || v === null || v === "") return "na";
  return String(v).trim();
}

return items.map(item => {
  const alert = item.json;

  // Better bucket: Use the already-fixed ISO timestamp from Asset Enrichment
  let bucketTime = alert.timestamps?.original;
  if (!bucketTime) bucketTime = new Date();
  
  const eventTime = new Date(bucketTime);
  // Create a stable 5-minute bucket string (YYYY-MM-DDTHH:mm) 
  const year = eventTime.getUTCFullYear();
  const month = String(eventTime.getUTCMonth() + 1).padStart(2, '0');
  const day = String(eventTime.getUTCDate()).padStart(2, '0');
  const hour = String(eventTime.getUTCHours()).padStart(2, '0');
  const minute = String(Math.floor(eventTime.getUTCMinutes() / 5) * 5).padStart(2, '0');
  
  const bucket_5m = `${year}-${month}-${day}T${hour}:${minute}:00Z`;
  alert.timestamps.bucket_5m = bucket_5m;

  // === Much stronger dedup_key ===
  const ruleName = safe(alert.rule?.name);
  const srcIp = safe(alert.network?.src_ip);
  const dstIp = safe(alert.network?.dst_ip);
  const srcHostname = safe(alert.asset_context?.src_asset?.hostname);
  const mitreKey = alert.rule?.mitre && alert.rule.mitre.length > 0 
    ? safe(alert.rule.mitre[0].tactic?.id || "na") 
    : "na";

  alert.dedup_key = [
    ruleName,
    srcIp,
    dstIp,
    srcHostname,           // Very important for process alerts
    mitreKey,              // Helps distinguish different tactics on same host
    bucket_5m
  ].join("|");

  return { json: alert };
});
