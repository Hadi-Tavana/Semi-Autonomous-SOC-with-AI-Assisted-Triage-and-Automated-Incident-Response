return items.map(item => {
  const i = item.json;

  const verdict = i.final_verdict;
  const alert = i.alert || {};
  const score = i.risk_score || 0;

  let decision = {
    action: null,
    priority: null,
    playbook: null,
    reason: null
  };

  // =========================
  // HIGH RISK → FULL RESPONSE
  // =========================
  if (verdict === "HIGH") {
    decision.action = "create_case";

    // Prioritize stronger attacks
    if (score >= 90) {
      decision.priority = "P1";
    } else {
      decision.priority = "P2";
    }

    // Map playbooks
    if (alert.alert_type === "powershell_execution") {
      decision.playbook = "EDR_Containment";
    } 
    else if (alert.alert_type === "web_activity") {
      decision.playbook = "Web_Server_Compromise";
    } 
    else {
      decision.playbook = "Generic_Threat_Investigation";
    }

    decision.reason = "High risk behavior + correlation detected";
  }

  // =========================
  // MEDIUM → INVESTIGATE
  // =========================
  else if (verdict === "MEDIUM") {
    decision.action = "create_alert";

    decision.priority = "P3";
    decision.playbook = "Threat_Hunting";

    decision.reason = "Suspicious behavior requires investigation";
  }

  // =========================
  // LOW → SUPPRESS / LOG
  // =========================
  else {
    if (alert.alert_type === "benign_update_activity") {
      decision.action = "auto_close";
      decision.reason = "Known benign update traffic";
    } else {
      decision.action = "log_only";
      decision.reason = "Low risk signal";
    }

    decision.priority = "P5";
    decision.playbook = "None";
  }

  // Attach decision
  i.decision = decision;

  return { json: i };
});
