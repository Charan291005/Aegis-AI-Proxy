"""Live test demonstrating how Antigravity communicates through Aegis."""
import subprocess
import json

def test_antigravity_mcp_call():
    print("\n" + "=" * 70)
    print("   AEGIS <-> ANTIGRAVITY MCP LIVE AGENT CALL")
    print("=" * 70)

    # 1. Simulate Antigravity AI Agent calling query_database
    agent_request = {
        "jsonrpc": "2.0",
        "id": "antigravity-req-001",
        "method": "tools/call",
        "params": {
            "name": "query_database",
            "arguments": {"customer_id": "cust_9921"},
            "_meta": {"client": "Antigravity-AI-Agent", "session_id": "sess-operator-002"}
        }
    }

    print("\n[1] Antigravity Agent sends MCP request to Aegis:")
    print(json.dumps(agent_request, indent=2))

    # 2. Pipe through the mcp_bridge to Aegis Gateway
    proc = subprocess.Popen(
        ["python", "scripts/mcp_bridge.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True
    )
    stdout, _ = proc.communicate(json.dumps(agent_request) + "\n")

    # 3. Parse and display Aegis sanitized response
    response_data = json.loads(stdout.strip())
    print("\n[2] Aegis Gateway sanitizes return payload and delivers to Antigravity:")
    print(json.dumps(response_data, indent=2))

    sanitized_text = response_data.get("result", {}).get("content", [{}])[0].get("text", "")
    print("\n[3] What the AI Agent actually receives in its context:")
    print(f'    "{sanitized_text}"')

    # 4. Verification Check
    has_redaction = "<REDACTED_PII>" in sanitized_text
    no_leak = "4111-1111-1111-1111" not in sanitized_text and "jane.doe@example.com" not in sanitized_text

    print("\n" + "-" * 70)
    if has_redaction and no_leak:
        print(" [+] VERIFICATION PASSED: Real Credit Card and Email were REDACTED!")
        print("     The AI Model never sees raw customer credentials.")
    else:
        print(" [!] VERIFICATION FAILED: Data was not sanitized.")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    test_antigravity_mcp_call()
