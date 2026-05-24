# Antigravity Simple Reverse Engineering MCP Server
# Implements MCP over stdio using standard Python JSON-RPC 2.0.

import sys
import json
import os
import subprocess

# Workspace dir is set dynamically to the script's directory for portability
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load configuration from local JSON config if present (ignored by Git)
# or fallback to environment variables.
GHIDRA_HEADLESS = ""
IDA_EXECUTABLE = ""

local_config_path = os.path.join(WORKSPACE_DIR, "mcp_local_config.json")
if os.path.exists(local_config_path):
    try:
        with open(local_config_path, "r", encoding="utf-8") as config_f:
            config_data = json.load(config_f)
            GHIDRA_HEADLESS = config_data.get("ghidra_headless", "")
            IDA_EXECUTABLE = config_data.get("ida_executable", "")
    except Exception as e:
        sys.stderr.write(f"[Server Log] Warning: Failed to load local config: {e}\n")

# Fallback to environment variables if config was not found/empty
if not GHIDRA_HEADLESS:
    GHIDRA_HEADLESS = os.environ.get("GHIDRA_HEADLESS", "")
if not IDA_EXECUTABLE:
    IDA_EXECUTABLE = os.environ.get("IDA_EXECUTABLE", "")

# These can be customized or passed as arguments to analyze_with_* commands
GAME_BINARY = os.path.join(WORKSPACE_DIR, "game")
GHIDRA_EXPORT_SCRIPT = os.path.join(WORKSPACE_DIR, "GhidraExport.java")
IDA_EXPORT_SCRIPT = os.path.join(WORKSPACE_DIR, "ida_export.py")

GHIDRA_CACHE = os.path.join(WORKSPACE_DIR, "ghidra_analysis.json")
IDA_CACHE = os.path.join(WORKSPACE_DIR, "ida_analysis.json")

def log(message):
    """Log to stderr so we don't interfere with the stdout JSON-RPC stream."""
    sys.stderr.write(f"[Server Log] {message}\n")
    sys.stderr.flush()

def read_cache(cache_path):
    if not os.path.exists(cache_path):
        return None
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"Error reading cache {cache_path}: {e}")
        return None

def run_ghidra_analysis(binary_path=None):
    target_binary = binary_path or GAME_BINARY
    if not os.path.exists(target_binary):
        return f"Error: Target binary {target_binary} not found."
        
    log(f"Running Ghidra headless analysis on {target_binary}...")
    proj_dir = os.path.join(WORKSPACE_DIR, "ghidra_proj")
    os.makedirs(proj_dir, exist_ok=True)
    
    cmd = [
        GHIDRA_HEADLESS,
        proj_dir,
        "GhidraProj",
        "-scriptPath", WORKSPACE_DIR,
        "-import", target_binary,
        "-overwrite",
        "-postScript", "GhidraExport.java",
        "-deleteProject"
    ]
    
    log(f"Executing: {' '.join(cmd)}")
    # Run the process
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    
    log(f"Ghidra STDOUT: {res.stdout[-1000:]}")
    log(f"Ghidra STDERR: {res.stderr[-1000:]}")
    
    if os.path.exists(GHIDRA_CACHE):
        return "Ghidra analysis successfully completed. Cache built!"
    else:
        return f"Ghidra analysis finished with exit code {res.returncode}, but ghidra_analysis.json was not created.\n\nError output:\n{res.stderr[-2000:]}"

def run_ida_analysis(binary_path=None):
    target_binary = binary_path or GAME_BINARY
    if not os.path.exists(target_binary):
        return f"Error: Target binary {target_binary} not found."
        
    log(f"Running IDA Pro headless analysis on {target_binary}...")
    
    cmd = [
        IDA_EXECUTABLE,
        "-A",
        f"-S{IDA_EXPORT_SCRIPT}",
        target_binary
    ]
    
    log(f"Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    
    log(f"IDA STDOUT: {res.stdout[-1000:]}")
    log(f"IDA STDERR: {res.stderr[-1000:]}")
    
    # Check if database has been created and script output file exists
    if os.path.exists(IDA_CACHE):
        return "IDA analysis successfully completed. Cache built!"
    else:
        # Check if it was a licensing error
        err_msg = res.stdout + res.stderr
        if "License not yet accepted" in err_msg or "License" in err_msg:
            return "Error: IDA license has not yet been accepted. Please open the GUI version of IDA Pro once on your desktop, accept the license agreement, close IDA, and try again."
        return f"IDA analysis finished with exit code {res.returncode}, but ida_analysis.json was not created.\n\nOutput:\n{err_msg[-2000:]}"

def handle_list_functions():
    # Try Ghidra cache first, then IDA
    cache = read_cache(GHIDRA_CACHE)
    source = "Ghidra"
    if not cache:
        cache = read_cache(IDA_CACHE)
        source = "IDA Pro"
        
    if not cache:
        return "No analysis cache found. Please run analyze_with_ghidra or analyze_with_ida first."
        
    functions = cache.get("functions", {})
    output_lines = [f"Function listing from {source} (Total: {len(functions)}):"]
    for name, f_info in sorted(functions.items()):
        output_lines.append(f"- {name} @ {f_info.get('entry')}")
    return "\n".join(output_lines)

def handle_decompile_function(func_name):
    # Try Ghidra cache first, then IDA
    cache = read_cache(GHIDRA_CACHE)
    if not cache:
        cache = read_cache(IDA_CACHE)
        
    if not cache:
        return "No analysis cache found. Please run analyze_with_ghidra or analyze_with_ida first."
        
    functions = cache.get("functions", {})
    # Case-insensitive lookup fallback
    match = functions.get(func_name)
    if not match:
        for name, f_info in functions.items():
            if name.lower() == func_name.lower():
                match = f_info
                break
                
    if not match:
        return f"Function '{func_name}' not found. Use list_functions to see available functions."
        
    return f"// Function: {match['name']} @ {match['entry']}\n\n{match['decompiled']}"

def handle_disassemble_function(func_name):
    cache = read_cache(GHIDRA_CACHE)
    if not cache:
        cache = read_cache(IDA_CACHE)
        
    if not cache:
        return "No analysis cache found. Please run analyze_with_ghidra or analyze_with_ida first."
        
    functions = cache.get("functions", {})
    match = functions.get(func_name)
    if not match:
        for name, f_info in functions.items():
            if name.lower() == func_name.lower():
                match = f_info
                break
                
    if not match:
        return f"Function '{func_name}' not found."
        
    return f"; Function: {match['name']} @ {match['entry']}\n\n{match['disassembly']}"

# Available tools schema
TOOLS_LIST = [
    {
        "name": "analyze_with_ghidra",
        "description": "Decompile and disassemble a binary using Ghidra in headless mode. Builds a local cache so function lookups are instant.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Optional absolute path to the target binary. Defaults to 'game' in the script directory."
                }
            }
        }
    },
    {
        "name": "analyze_with_ida",
        "description": "Decompile and disassemble a binary using IDA Pro in headless mode. Builds a local cache so function lookups are instant.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Optional absolute path to the target binary. Defaults to 'game' in the script directory."
                }
            }
        }
    },
    {
        "name": "list_functions",
        "description": "List all functions extracted from the analyzed binary cache.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "decompile_function",
        "description": "Retrieve the decompiled C pseudo-code for a specific function.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "func_name": {
                    "type": "string",
                    "description": "The name of the function to decompile (e.g., 'main' or 'sym.imp.strcmp')"
                }
            },
            "required": ["func_name"]
        }
    },
    {
        "name": "disassemble_function",
        "description": "Retrieve assembly instructions for a specific function.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "func_name": {
                    "type": "string",
                    "description": "The name of the function to disassemble"
                }
            },
            "required": ["func_name"]
        }
    }
]

def main():
    log("Starting Antigravity RE MCP Server...")
    
    # Fast stdin line reader
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            
            # Keep protocol version 2024-11-05
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "antigravity-re",
                            "version": "1.0.0"
                        }
                    }
                }
            elif method == "notifications/initialized" or method == "initialized":
                # Notifications don't need a response
                continue
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS_LIST
                    }
                }
            elif method == "tools/call":
                params = req.get("params", {})
                tool_name = params.get("name")
                args = params.get("arguments", {})
                
                log(f"Calling tool: {tool_name} with args: {args}")
                
                try:
                    if tool_name == "analyze_with_ghidra":
                        result_text = run_ghidra_analysis(args.get("binary_path"))
                    elif tool_name == "analyze_with_ida":
                        result_text = run_ida_analysis(args.get("binary_path"))
                    elif tool_name == "list_functions":
                        result_text = handle_list_functions()
                    elif tool_name == "decompile_function":
                        result_text = handle_decompile_function(args.get("func_name"))
                    elif tool_name == "disassemble_function":
                        result_text = handle_disassemble_function(args.get("func_name"))
                    else:
                        result_text = f"Error: Tool '{tool_name}' not found."
                        
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": result_text
                                }
                            ]
                        }
                    }
                except Exception as ex:
                    log(f"Exception handling tool call {tool_name}: {ex}")
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": str(ex)
                        }
                    }
            else:
                if req_id is not None:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method {method} not found"
                        }
                    }
                else:
                    continue
            
            # Send response to client
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            
        except json.JSONDecodeError:
            log("Invalid JSON received.")
        except Exception as e:
            log(f"Global exception in main loop: {e}")
            break

if __name__ == "__main__":
    main()
