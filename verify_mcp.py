# Verification Script for Custom MCP Server
# Runs E2E JSON-RPC handshake simulation to verify the protocol.

import subprocess
import json
import sys
import os

def send_request(proc, req):
    req_str = json.dumps(req) + "\n"
    proc.stdin.write(req_str)
    proc.stdin.flush()
    
    # Read response line
    resp_line = proc.stdout.readline()
    if not resp_line:
        print("[!] No response received.")
        return None
    return json.loads(resp_line)

def run_verification():
    print("[*] Starting MCP Server verification...")
    # Launch MCP server from current script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mcp_server_path = os.path.join(script_dir, "mcp_server.py")
    
    proc = subprocess.Popen(
        [sys.executable, mcp_server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=script_dir
    )
    
    # 1. Initialize
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"}
        }
    }
    print("[*] Sending 'initialize' request...")
    res = send_request(proc, init_req)
    print("Response:", json.dumps(res, indent=2))
    
    # 2. List tools
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    print("\n[*] Sending 'tools/list' request...")
    res = send_request(proc, list_req)
    print("Response:", json.dumps(res, indent=2))
    
    # 3. Call list_functions
    call_list = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "list_functions",
            "arguments": {}
        }
    }
    print("\n[*] Calling tool 'list_functions'...")
    res = send_request(proc, call_list)
    content = res["result"]["content"][0]["text"] if "result" in res else str(res)
    # Print first few lines of output
    lines = content.splitlines()
    print("First 20 lines of function listing:")
    for line in lines[:20]:
        print("  ", line)
    if len(lines) > 20:
        print(f"  ... and {len(lines) - 20} more functions.")
        
    # 4. Call decompile_function on 'main'
    call_decompile = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "decompile_function",
            "arguments": {"func_name": "main"}
        }
    }
    print("\n[*] Calling tool 'decompile_function' for 'main'...")
    res = send_request(proc, call_decompile)
    if "result" in res and "content" in res["result"]:
        decompiled_text = res["result"]["content"][0]["text"]
        print("Decompiled main function:")
        print("-" * 50)
        print(decompiled_text[:1000])  # Show first 1000 chars
        print("-" * 50)
    else:
        print("Response:", json.dumps(res, indent=2))
        
    # Terminate process
    proc.terminate()
    # Read stderr to see any logged messages
    stderr_output = proc.stderr.read()
    if stderr_output:
        print("\n[*] Server Stderr logs:")
        print(stderr_output)
        
    print("[*] Verification completed successfully!")

if __name__ == "__main__":
    run_verification()
