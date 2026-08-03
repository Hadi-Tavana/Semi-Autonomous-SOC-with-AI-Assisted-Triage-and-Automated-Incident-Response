import subprocess
import time
import sys
import json
import re

API_CONFIG = "api.config.yaml"
ARTIFACT = "Custom.Windows.Remediation.Glob.Aggressive.Multi"

def run_vql_raw(query):
    result = subprocess.run(
        ["/home/ubuntu/.local/bin/pyvelociraptor", "--config", API_CONFIG, query],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"VQL Error: {result.stderr.strip()}", file=sys.stderr)
        return ""
    return result.stdout

def parse_vql_rows(output):
    if not output:
        return []
    try:
        lines = output.strip().splitlines()
        for line in reversed(lines):
            line = line.strip()
            if line.startswith('[') or '{' in line:
                json_str = line.replace("'", '"')
                data = json.loads(json_str)
                return data if isinstance(data, list) else [data]
    except:
        pass
    return []

def extract_flow_id(output):
    patterns = [r"flow_id['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]", r"(F\.[A-Z0-9]+)"]
    for p in patterns:
        m = re.search(p, output)
        if m:
            return m.group(1)
    return None

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"status": "invalid_args"}))
        return

    file_path = sys.argv[1].replace("\\", "\\\\")

    # Get active clients
    clients = parse_vql_rows(run_vql_raw("""
        SELECT client_id FROM clients()
        WHERE now() - last_seen_at < 600000000
    """))

    print(f"Found {len(clients)} active client(s)", file=sys.stderr)
    if not clients:
        print(json.dumps({"status": "no_active_clients"}))
        return

    # Launch flows
    flows = []
    for c in clients:
        cid = c.get("client_id")
        flow_query = f"""
        SELECT collect_client(
            client_id='{cid}',
            artifacts='{ARTIFACT}',
            spec=dict(`{ARTIFACT}`=dict(TargetGlobs='{file_path}'))
        ) FROM scope()
        """
        out = run_vql_raw(flow_query)
        fid = extract_flow_id(out)
        if fid:
            flows.append({"client_id": cid, "flow_id": fid})
            print(f"✓ Flow created → {cid} | {fid}", file=sys.stderr)

    if not flows:
        print(json.dumps({"status": "flow_creation_failed"}))
        return

    print("Waiting for remediation to complete...", file=sys.stderr)
    time.sleep(15)

    final_results = []
    success_clients = []

    for f in flows:
        cid = f["client_id"]
        fid = f["flow_id"]

        status_rows = parse_vql_rows(run_vql_raw(f"""
            SELECT state, total_collected_rows 
            FROM flows(client_id='{cid}', flow_id='{fid}')
        """))

        print(f"Flow {fid} status: {status_rows}", file=sys.stderr)

        if status_rows:
            row = status_rows[0]
            state = row.get("state", "")
            collected = int(row.get("total_collected_rows", 0))

            if state == "FINISHED" and collected >= 1:
                success_clients.append(cid)
                final_results.append({
                    "client_id": cid,
                    "path": file_path,
                    "status": "deleted"
                })
                print(f"✓ SUCCESS - Deletion confirmed on {cid} (rows collected: {collected})", file=sys.stderr)

    status = "success" if final_results else "not_found"
    print(json.dumps({
        "status": status,
        "results": final_results,
        "success_count": len(final_results)
    }))

if __name__ == "__main__":
    main()
