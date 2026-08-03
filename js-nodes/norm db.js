return items.map(item => {
  const text = item.json.output;

  return {
    json: {
      src_ip: text.match(/Source IP:\s*([0-9.]+)/)?.[1] || null,
      dst_ip: text.match(/Destination IP:\s*([0-9.]+)/)?.[1] || null,
      url: text.match(/URL accessed:\s*(.*)/)?.[1] || null,
      ports: text.match(/Ports used:\s*(.*)/)?.[1] || null,
      risk: text.includes("Low risk") ? "low" :
            text.includes("Medium risk") ? "medium" : "unknown",
      full_report: text.replace(/\n/g, " ").trim(),
      created_at: new Date().toISOString()
    }
  };
});
