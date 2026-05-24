// Ghidra Headless Export Script
// @author Antigravity
// @category Export

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.FileWriter;
import java.io.File;

public class GhidraExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("[*] Starting Ghidra Java analysis export...");
        if (currentProgram == null) {
            println("[!] No current program loaded.");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(currentProgram)) {
            println("[!] Failed to open program in decompiler.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"program_name\": \"").append(currentProgram.getName()).append("\",\n");
        sb.append("  \"functions\": {\n");

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        boolean firstFunc = true;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            String funcName = func.getName();
            String entryPoint = func.getEntryPoint().toString();
            println("[*] Decompiling " + funcName + " @ " + entryPoint);

            DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            String decompiledC = "";
            if (results != null && results.decompileCompleted()) {
                decompiledC = results.getDecompiledFunction().getC();
            } else {
                decompiledC = "/* Decompilation failed or timed out */";
            }

            // Get Disassembly
            StringBuilder disasm = new StringBuilder();
            InstructionIterator insts = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (insts.hasNext()) {
                Instruction inst = insts.next();
                String addr = inst.getAddress().toString();
                disasm.append(addr).append(" ").append(inst.toString()).append("\n");
            }

            if (!firstFunc) {
                sb.append(",\n");
            }
            firstFunc = false;

            sb.append("    \"").append(funcName).append("\": {\n");
            sb.append("      \"name\": \"").append(funcName).append("\",\n");
            sb.append("      \"entry\": \"").append(entryPoint).append("\",\n");
            sb.append("      \"decompiled\": ").append(escapeJson(decompiledC)).append(",\n");
            sb.append("      \"disassembly\": ").append(escapeJson(disasm.toString())).append("\n");
            sb.append("    }");
        }

        sb.append("\n  }\n");
        sb.append("}\n");

        // Dynamically get script directory to avoid hardcoded paths
        File scriptFile = getSourceFile();
        String scriptDir = scriptFile.getParent();
        String outputPath = scriptDir + File.separator + "ghidra_analysis.json";

        FileWriter writer = new FileWriter(new File(outputPath));
        writer.write(sb.toString());
        writer.close();

        println("[*] Ghidra export completed! Written to: " + outputPath);
    }

    private String escapeJson(String str) {
        if (str == null) return "null";
        StringBuilder sb = new StringBuilder();
        sb.append("\"");
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < ' ') {
                        String t = "000" + Integer.toHexString(c);
                        sb.append("\\u").append(t.substring(t.length() - 4));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }
}
