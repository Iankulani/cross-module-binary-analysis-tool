# -*- coding: utf-8 -*-
"""
Created on Mon Jan 13 20:39:25 2025

@author: IAN CARTER KULANI

"""


from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Taint Sink Detector")
print(Fore.GREEN+font)

import os
from pycparser import c_parser, c_ast
import re

# Step 1: Parse a single C file
def parse_c_code(file_path):
    with open(file_path, 'r') as file:
        code = file.read()
    
    parser = c_parser.CParser()
    try:
        ast = parser.parse(code)
        return ast
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
        return None

# Step 2: Parse multiple C files in a directory
def parse_multiple_files(directory):
    all_asts = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.c'):
                file_path = os.path.join(root, file)
                ast = parse_c_code(file_path)
                if ast:
                    all_asts[file_path] = ast
    return all_asts

# Step 3: Collect function declarations (to resolve cross-module calls)
def collect_function_declarations(ast, file_name):
    function_declarations = {}
    for node in ast.ext:
        if isinstance(node, c_ast.Decl) and isinstance(node.type, c_ast.FuncType):
            function_declarations[node.name] = {
                "type": node.type,
                "file": file_name
            }
    return function_declarations

# Step 4: Collect variable declarations and input sources (taint sources)
def collect_input_sources(ast):
    input_sources = []
    for node in ast.ext:
        if isinstance(node, c_ast.FuncCall):
            if node.name.name in ['scanf', 'gets', 'fgets']:
                input_sources.append(node)
    return input_sources

# Step 5: Track Taint Propagation Across Multiple Files
def track_taint_propagation(across_files, input_sources):
    tainted_variables = set()
    
    # Add input sources as tainted variables
    for file, sources in input_sources.items():
        for source in sources:
            for arg in source.args.exprs:
                if isinstance(arg, c_ast.ID):
                    tainted_variables.add(arg.name)
    
    # Track propagation across different files
    for file, ast in across_files.items():
        for node in ast.ext:
            if isinstance(node, c_ast.Decl):
                if isinstance(node.init, c_ast.ID) and node.init.name in tainted_variables:
                    tainted_variables.add(node.name)
            if isinstance(node, c_ast.Assignment):
                if isinstance(node.lvalue, c_ast.ID) and node.rvalue:
                    if isinstance(node.rvalue, c_ast.ID) and node.rvalue.name in tainted_variables:
                        tainted_variables.add(node.lvalue.name)
    
    return tainted_variables

# Step 6: Detect Taint Sinks in Multiple Files
def detect_taint_sinks(across_files, tainted_variables):
    taint_sinks = []
    dangerous_functions = ['system', 'exec', 'strcpy', 'sprintf', 'fopen', 'popen']
    
    # Look for function calls that could be dangerous
    for file, ast in across_files.items():
        for node in ast.ext:
            if isinstance(node, c_ast.FuncCall):
                if node.name.name in dangerous_functions:
                    for arg in node.args.exprs:
                        if isinstance(arg, c_ast.ID) and arg.name in tainted_variables:
                            taint_sinks.append((node.name.name, arg.name, file))
    
    return taint_sinks

# Step 7: Report Taint Vulnerabilities
def report_vulnerabilities(taint_sinks):
    if taint_sinks:
        print("Potential taint sinks detected:")
        for sink in taint_sinks:
            print(f"File: {sink[2]} | Function: {sink[0]} - Tainted variable: {sink[1]}")
    else:
        print("No potential taint sinks detected.")

# Step 8: Main Function to Run the Tool
def main():
    # Input directory with C files
    project_directory = input("Enter the path to the directory:")

    # Step 1: Parse multiple C files in the project directory
    all_asts = parse_multiple_files(project_directory)
    
    # Step 2: Collect function declarations and input sources across all files
    function_declarations = {}
    input_sources = {}
    
    for file, ast in all_asts.items():
        function_declarations.update(collect_function_declarations(ast, file))
        input_sources[file] = collect_input_sources(ast)

    # Step 3: Track taint propagation across all files
    tainted_variables = track_taint_propagation(all_asts, input_sources)

    # Step 4: Detect potential taint sinks across all files
    taint_sinks = detect_taint_sinks(all_asts, tainted_variables)

    # Step 5: Report vulnerabilities
    report_vulnerabilities(taint_sinks)

if __name__ == "__main__":
    main()
