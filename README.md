# Model Context Protocol (MCP) Server for Ghidra & IDA Pro

A custom Model Context Protocol (MCP) server that interfaces with **Ghidra** and **IDA Pro** to provide interactive decompilation, disassembly, and binary analysis capabilities to AI coding assistants (such as Cursor, Claude Desktop, and Antigravity IDE).

## Architecture

Traditional headless analysis is too slow to execute in real-time on every query. This server uses a **two-phase cache-based architecture**:
1. **Pre-Analysis Phase**: Run Ghidra or IDA Pro in headless mode *once* on your target binary to export all functions, decompiled pseudo-code, and assembly listings into a local JSON database (`ghidra_analysis.json` or `ida_analysis.json`).
2. **Instant Query Phase**: The MCP server handles client requests (JSON-RPC) instantly by reading the pre-generated database files.

---

## Exposed MCP Tools

The server exposes the following JSON-RPC commands:
*   `analyze_with_ghidra`: Triggers headless analysis of a target binary using Ghidra and builds the local function cache.
*   `analyze_with_ida`: Triggers headless analysis of a target binary using IDA Pro and builds the local function cache.
*   `list_functions`: Instantly lists all functions found in the database.
*   `decompile_function`: Retrieves decompiled C pseudo-code for a function.
*   `disassemble_function`: Retrieves assembly instructions for a function.

---

## Getting Started

### 1. Prerequisites
*   Python 3.11+
*   **Ghidra** (with the `analyzeHeadless` utility) OR **IDA Pro** (with Hex-Rays decompiler and `idat` utility).
*   Ghidra requires Java JDK configured on your system.

### 2. Configure Paths
Edit the path variables at the top of `mcp_server.py` to match the installation locations on your system:
```python
GHIDRA_HEADLESS = r"C:\path\to\ghidra\support\analyzeHeadless.bat"
IDA_EXECUTABLE = r"C:\path\to\IDA\idat.exe"
```

### 3. Verification
Run the verification script to simulate the JSON-RPC interface and verify correct setup:
```bash
python verify_mcp.py
```

---

## IDE Integration Configuration

To integrate this MCP server with your AI assistant, add it to your configuration (e.g., in Claude Desktop's `claude_desktop_config.json`, or the IDE's custom MCP settings):

```json
{
  "mcpServers": {
    "antigravity-re": {
      "command": "python",
      "args": ["C:/path/to/your/desktop/mcp-reverse-engineering/mcp_server.py"]
    }
  }
}
```

---

## License

This project is open-source and available under the [MIT License](LICENSE).
