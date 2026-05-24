# Ghidra Headless Export Script (Python/Jython)
# @author Antigravity
# @category Export

import json
import sys
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def run():
    print("[*] Starting Ghidra analysis export...")
    if currentProgram is None:
        print("[!] No current program loaded.")
        sys.exit(1)
        
    program_name = currentProgram.getName()
    print("[*] Program Name: {}".format(program_name))
    
    # Initialize Decompiler
    decomp = DecompInterface()
    if not decomp.openProgram(currentProgram):
        print("[!] Failed to open program in decompiler.")
        sys.exit(1)
        
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    
    functions_data = {}
    
    # Get all functions
    funcs = fm.getFunctions(True) # True means forward order
    for func in funcs:
        func_name = func.getName()
        entry_point = func.getEntryPoint().toString()
        print("[*] Decompiling {} @ {}".format(func_name, entry_point))
        
        # Decompile function
        decomp_results = decomp.decompileFunction(func, 30, monitor)
        decompiled_c = ""
        if decomp_results and decomp_results.decompileCompleted():
            decompiled_f = decomp_results.getDecompiledFunction()
            if decompiled_f:
                decompiled_c = decompiled_f.getC()
        else:
            decompiled_c = "/* Decompilation failed or timed out */"
            
        # Get Disassembly
        disasm_lines = []
        insts = listing.getInstructions(func.getBody(), True)
        for inst in insts:
            addr = inst.getAddress().toString()
            mnemonic = inst.getMnemonicString()
            operands = inst.getDefaultOperandRepresentationList()
            ops_str = ", ".join([str(op) for op in operands]) if operands else ""
            disasm_lines.append("{} {} {}".format(addr, mnemonic, ops_str))
            
        functions_data[func_name] = {
            "name": func_name,
            "entry": entry_point,
            "decompiled": decompiled_c,
            "disassembly": "\n".join(disasm_lines)
        }
        
    # Build complete report
    report = {
        "program_name": program_name,
        "functions": functions_data
    }
    
    # Dynamically resolve script's directory for output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "ghidra_analysis.json")
    
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print("[*] Ghidra export completed! Written to: {}".format(output_path))

if __name__ == "__main__":
    run()
