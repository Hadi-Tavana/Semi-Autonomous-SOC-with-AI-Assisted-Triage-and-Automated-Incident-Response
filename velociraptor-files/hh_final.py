import subprocess
import time
import sys
import json
import re

API_CONFIG = "api.config.yaml"
ARTIFACT = "Custom.Windows.Detection.SingleHashSearch"


def run_vql_raw(query):
    result = subprocess.run(
        ["/home/ubuntu/.local/bin/pyvelociraptor", "--config", API_CONFIG, query],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return ""

    return result.stdout


def extract_hunt_id(output):
    match = re.search(r"HuntId['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", output)
    return match.group(1) if match else None


def parse_vql_json(output):
    """
    Extract JSON-like list from Velociraptor output
    """
    try:
        json_part = output.split("\n\n")[-1]
        return json.loads(json_part.replace("'", '"'))
    except:
        return []


def main():
    if len(sys.argv) != 4:
        print(json.dumps({"status": "invalid_args"}))
        return

    hash_value = sys.argv[1].lower()
    hash_type = sys.argv[2].lower()
    target_glob = sys.argv[3]

    # ---------------------------
    # START HUNT
    # ---------------------------
    hunt_query = f"""
SELECT hunt(
    artifacts='{ARTIFACT}',
    spec=dict(`{ARTIFACT}`=dict(
        TargetGlobs='{target_glob}',
        HashType='{hash_type}',
        HashValue='{hash_value}'
    ))
) FROM scope()
"""

    hunt_output = run_vql_raw(hunt_query)
    hunt_id = extract_hunt_id(hunt_output)

    if not hunt_id:
        print(json.dumps({"status": "hunt_creation_failed"}))
        return

    # ---------------------------
    # POLLING
    # ---------------------------
    interval = 15
    max_wait = 300
    elapsed = 0
    final_results = []

    while elapsed < max_wait:
        results_query = f"""
SELECT Fqdn, ClientId, FullPath, Hash
FROM hunt_results(hunt_id='{hunt_id}')
"""
        output = run_vql_raw(results_query)
        parsed = parse_vql_json(output)

        if parsed:
            for row in parsed:
                if row.get("FullPath"):
                    final_results.append({
                        "client_id": row.get("ClientId"),
                        "hostname": row.get("Fqdn"),
                        "path": row.get("FullPath"),
                        "sha256": row.get("Hash", {}).get("SHA256")
                    })

            if final_results:
                break

        time.sleep(interval)
        elapsed += interval

    # ---------------------------
    # DELETE HUNT (SILENT)
    # ---------------------------
    delete_query = f"""
SELECT * FROM Artifact.Server.Hunts.CancelAndDelete(
    HuntId='{hunt_id}',
    DeleteAllFiles=true
)
"""
    _ = run_vql_raw(delete_query)  # ignore noisy output

    # ---------------------------
    # FINAL OUTPUT (ONLY JSON)
    # ---------------------------
    print(json.dumps({
        "status": "success" if final_results else "not_found",
        "hunt_id": hunt_id,
        "results": final_results
    }))


if __name__ == "__main__":
    main()
