return $input.all().map((item, index) => {

  // ✅ Always fetch original trigger item directly
  const triggerItem = $items("When Executed by Another Workflow")[index]?.json || {};

  // ✅ In IP flow, the whole object IS the alert
  const originalAlert = triggerItem;
  const indicatorValue = triggerItem.value || "unknown";

  // ✅ Fetch OSINT results safely
  const shodanData = $items("Shodan IP Search")[index]?.json || {};
  const abuseData = $items("AbuseIPDB IP Search")[index]?.json || {};
  const vtData = $items("VirusTotal IP Search")[index]?.json || {};

  return {
    json: {
      alert_id: originalAlert.alert_id || "unknown",
      type: "ip",
      value: indicatorValue,

      // ✅ FIXED: now correctly contains full alert
      alert: originalAlert,

      lookup_results: {
        shodan: {
          os: shodanData.os || "Unknown",
          ports: shodanData.ports || [],
          isp: shodanData.isp || "Unknown",
          raw: shodanData
        },
        abuseipdb: {
          score: abuseData.data?.abuseConfidenceScore || 0,
          country: abuseData.data?.countryCode || "N/A",
          usage_type: abuseData.data?.usageType || "Unknown",
          raw: abuseData
        },
        virustotal: {
          reputation: vtData.data?.attributes?.reputation || 0,
          malicious_votes: vtData.data?.attributes?.last_analysis_stats?.malicious || 0,

          // ✅ FIXED link interpolation
          link: `https://virustotal.com/ip-address/${indicatorValue}`,

          raw: vtData
        }
      }
    }
  };
});
