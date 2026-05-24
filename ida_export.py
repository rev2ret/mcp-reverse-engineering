# IDA Headless Export Script
# @author Antigravity

import idc
import idautils
import idaapi
import json
import os
import sys

def run():
    print("[*] Starting IDA Python analysis export...")
    # Try to initialize hexrays decompiler plugin
    if not idaapi.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available or licensed.")
        
    functions_data = {}
    
    # Iterate through all functions defined in the binary
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        print("[*] Exporting {} @ {}".format(func_name, hex(func_ea)))
        
        # Decompile function
        decompiled_c = ""
        try:
            cfunc = idaapi.decompile(func_ea)
            if cfunc:
                decompiled_c = str(cfunc)
            else:
                decompiled_c = "/* Decompilation failed: returned None */"
        except Exception as e:
            decompiled_c = "/* Decompilation failed: {} */".format(str(e))
            
        # Get Disassembly
        disasm_lines = []
        func_start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        for head in idautils.Heads(func_start, func_end):
            if idc.is_code(idc.get_full_flags(head)):
                disasm_lines.append("{}: {}".format(hex(head), idc.generate_disasm_line(head, 0)))
                
        functions_data[func_name] = {
            "name": func_name,
            "entry": hex(func_ea),
            "decompiled": decompiled_c,
            "disassembly": "\n".join(disasm_lines)
        }
        
    # Build complete report
    report = {
        "program_name": idc.get_input_file_path(),
        "functions": functions_data
    }
    
    # Dynamically resolve script's directory for output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, "ida_analysis.json")
    
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print("[*] IDA export completed! Written to: {}".format(output_path))
    # Exit IDA Pro
    idc.qexit(0)

if __name__ == "__main__":
    run()
