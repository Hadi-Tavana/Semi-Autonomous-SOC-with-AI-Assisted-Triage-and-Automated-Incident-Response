import subprocess
import sys

API_CONFIG = "api.config.yaml"
ARTIFACT = "Windows.Remediation.Quarantine"


def run_vql_raw(query):
    result = subprocess.run(
        ["/home/ubuntu/.local/bin/pyvelociraptor", "--config", API_CONFIG, query],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("ERROR:")
        print(result.stderr)
        sys.exit(1)

    return result.stdout


def main():
    if len(sys.argv) < 2:
        print("Usage: script.py <client_id> [message]")
        sys.exit(1)

    client_id = sys.argv[1]
    message = sys.argv[2] if len(sys.argv) > 2 else "Device quarantined by SOC"

    print(f"[+] Quarantining client {client_id}...\n")

    query = f"""
SELECT collect_client(
    client_id='{client_id}',
    artifacts='{ARTIFACT}',
    spec=dict(`{ARTIFACT}`=dict(
        PolicyName='VelociraptorQuarantine',
        MessageBox='{message}',
        RemovePolicy=false
    ))
) FROM scope()
"""

    output = run_vql_raw(query)

    print("=== RESPONSE ===\n")
    print(output)


if __name__ == "__main__":
    main()
