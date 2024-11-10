# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    DEBUG.py                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: ismherna <ismherna@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/07 21:37:58 by ismherna          #+#    #+#              #
#    Updated: 2024/11/07 21:37:59 by ismherna         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

import os
import hashlib
import numpy as np
import matplotlib.pyplot as plt
import capstone


def get_file_hash(file_path):
    """Genera el hash MD5 de un archivo."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def compare_files(file1, file2):
    """Compara dos archivos y devuelve un porcentaje de similitud basado en el número de bytes coincidentes."""
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()

    # Compara hasta la longitud del archivo más corto
    length = min(len(data1), len(data2))
    matches = sum(1 for i in range(length) if data1[i] == data2[i])
    similarity = matches / length * 100 if length > 0 else 0
    return similarity

def disassemble_file(file_path):
    """Desensambla un archivo binario y devuelve una lista de instrucciones."""
    with open(file_path, 'rb') as f:
        code = f.read()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = [instr.mnemonic + " " + instr.op_str for instr in md.disasm(code, 0x1000)]
    return instructions

def compare_instructions(instr1, instr2):
    """Compara dos listas de instrucciones ensambladas y devuelve un porcentaje de similitud."""
    min_len = min(len(instr1), len(instr2))
    matches = sum(1 for i in range(min_len) if instr1[i] == instr2[i])
    similarity = matches / min_len * 100 if min_len > 0 else 0
    return similarity

def find_executable_files(directory, pattern='a.out'):
    """Encuentra archivos ejecutables específicos en un directorio."""
    executables = []
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            if pattern in filename:
                file_path = os.path.join(dirpath, filename)
                if os.access(file_path, os.X_OK):
                    executables.append(file_path)
    return executables

def generate_heatmap(similarity_matrix, project_files, comparison_files, title, filename):
    """Genera un mapa de calor basado en la matriz de similitud."""
    fig, ax = plt.subplots()
    cax = ax.matshow(similarity_matrix, cmap='hot', vmin=0, vmax=100)
    plt.colorbar(cax, label="Similitud (%)")
    ax.set_xticks(np.arange(len(comparison_files)))
    ax.set_yticks(np.arange(len(project_files)))
    ax.set_xticklabels([os.path.basename(f) for f in comparison_files], rotation=90)
    ax.set_yticklabels([os.path.basename(f) for f in project_files])
    plt.xlabel('Comparison Repos')
    plt.ylabel('Project Files')
    plt.title(title)

    # Crear carpeta OUTPUT si no existe
    output_dir = '../OUTPUT'
    os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(output_dir, filename)
    plt.savefig(output_path)
    plt.close(fig)

def extract_functions(file_path):
    """Extrae las funciones de un archivo binario desensamblado y las guarda en un archivo."""
    instructions = disassemble_file(file_path)
    functions = {}
    current_function = None
    for instr in instructions:
        if instr.startswith("call"):
            called_function = instr.split()[1]
            if current_function:
                functions[current_function].append(called_function)
        elif instr.startswith("ret"):
            current_function = None
        else:
            if current_function is None:
                current_function = instr
                functions[current_function] = []

    # Guardar las funciones en un archivo en el directorio OUTPUT
    output_dir = '../OUTPUT'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, os.path.basename(file_path) + '_functions.txt')
    with open(output_file, 'w') as f:
        for func, calls in functions.items():
            f.write(f"Function: {func}\n")
            for call in calls:
                f.write(f"  Calls: {call}\n")
            f.write("\n")
    return functions

def compare_functions(funcs1, funcs2):
    """Compara dos diccionarios de funciones y devuelve un porcentaje de similitud."""
    all_funcs = set(funcs1.keys()).union(set(funcs2.keys()))
    matches = sum(1 for func in all_funcs if funcs1.get(func) == funcs2.get(func))
    similarity = matches / len(all_funcs) * 100 if all_funcs else 0
    return similarity

def plagiarism_checker_with_functions(project_dir, comparison_dir):
    """Comprueba la similitud entre ejecutables en dos directorios específicos, incluyendo funciones secundarias."""
    project_files = find_executable_files(project_dir)
    comparison_files = find_executable_files(comparison_dir)

    if not project_files:
        print("No se encontraron archivos ejecutables en la carpeta de proyectos.")
        return
    if not comparison_files:
        print("No se encontraron archivos ejecutables en la carpeta de comparación.")
        return

    # Matrices de similitud para comparación por bytes, lógica y funciones
    byte_similarity_matrix = np.zeros((len(project_files), len(comparison_files)))
    logical_similarity_matrix = np.zeros((len(project_files), len(comparison_files)))
    function_similarity_matrix = np.zeros((len(project_files), len(comparison_files)))

    for i, project_file in enumerate(project_files):
        for j, comparison_file in enumerate(comparison_files):
            # Comparación por bytes
            byte_similarity_matrix[i, j] = compare_files(project_file, comparison_file)
            
            # Desensamblado y comparación lógica
            project_instructions = disassemble_file(project_file)
            comparison_instructions = disassemble_file(comparison_file)
            logical_similarity_matrix[i, j] = compare_instructions(project_instructions, comparison_instructions)

            # Comparación de funciones
            project_functions = extract_functions(project_file)
            comparison_functions = extract_functions(comparison_file)
            function_similarity_matrix[i, j] = compare_functions(project_functions, comparison_functions)

    # Genera heatmaps separados
    generate_heatmap(byte_similarity_matrix, project_files, comparison_files, "Similitud por Bytes", 'byte_similarity_heatmap.png')
    generate_heatmap(logical_similarity_matrix, project_files, comparison_files, "Similitud Lógica (Capstone)", 'logical_similarity_heatmap.png')
    generate_heatmap(function_similarity_matrix, project_files, comparison_files, "Similitud de Funciones", 'function_similarity_heatmap.png')

    # Calcula y muestra las similitudes promedio
    avg_byte_similarity = np.mean(byte_similarity_matrix)
    avg_logical_similarity = np.mean(logical_similarity_matrix)
    avg_function_similarity = np.mean(function_similarity_matrix)
    print(f"Average byte similarity: {avg_byte_similarity:.2f}%")
    print("Byte similarity matrix:")
    print(byte_similarity_matrix)
    print(f"Average logical similarity: {avg_logical_similarity:.2f}%")
    print("Logical similarity matrix:")
    print(logical_similarity_matrix)
    print(f"Average function similarity: {avg_function_similarity:.2f}%")
    print("Function similarity matrix:")
    print(function_similarity_matrix)

if __name__ == "__main__":
    project_dir = '../TARGET_DIR'  # Ruta relativa a TARGET_DIR desde PD_push_swap
    comparison_dir = 'db_comparison_repos'

    # Imprime el directorio actual
    print("Directorio actual:", os.getcwd())

    # Imprime la ruta completa
    full_path = os.path.abspath(project_dir)
    print("Ruta a TARGET_DIR:", full_path)

    # Verifica si la ruta existe
    if os.path.exists(full_path):
        print(f"La ruta {full_path} existe.")
        plagiarism_checker_with_functions(full_path, comparison_dir)
    else:
        print(f"La ruta {full_path} no existe.")
