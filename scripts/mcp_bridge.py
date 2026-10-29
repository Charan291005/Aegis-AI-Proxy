"""Lightweight stdio-to-HTTP bridge connecting Antigravity to Aegis Gateway."""
import sys
import json
import urllib.request

AEGIS_URL = "http://localhost:8000/mcp/dispatch"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer aegis_super_secret_bearer_token_2026_demo",
    "X-Session-ID": "sess-operator-002",
}


def main():
    # Read unbuffered line-by-line JSON-RPC messages from Antigravity over stdin
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = urllib.request.Request(AEGIS_URL, data=line.encode("utf-8"), headers=HEADERS)
            with urllib.request.urlopen(req) as resp:
                output = resp.read().decode("utf-8")
                sys.stdout.write(output + "\n")
                sys.stdout.flush()
        except Exception as err:
            err_resp = {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(err)}}
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
