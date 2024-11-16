# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    philo.py                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: razamora <razamora@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/04 13:40:07 by ismherna          #+#    #+#              #
#    Updated: 2024/11/16 19:53:10 by razamora         ###   ########.fr        #
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

def find_executable_files(directory, pattern='philo'):# TODO
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




##### PARTE EN LA QUE AÑADIR REPOSITORIOS DE COMPARACIÓN #####
def get_repo_name(repo_number):
    """Devuelve el nombre del repositorio según el número de comparación."""
    if repo_number == "1":
        return "Repo_Alpha"
    elif repo_number == "2":
        return "Repo_Beta"
    elif repo_number == "3":
        return "Repo_Gamma"
    elif repo_number == "4":
        return "Repo_Delta"
    elif repo_number == "5":
        return "Repo_Epsilon"
    else:
        return "Unknown Repo"







# Función para color según el porcentaje
def get_color_for_similarity(similarity):
    """Devuelve el código de color ANSI según el nivel de similitud."""
    if similarity >= 75:
        return "\033[91m"  # Rojo
    elif similarity >= 50:
        return "\033[93m"  # Naranja
    elif similarity >= 25:
        return "\033[93m"  # Amarillo
    else:
        return "\033[92m"  # Verde

def reset_color():
    """Restablece el color de salida a la terminal."""
    return "\033[0m"

# Resto de las funciones (get_file_hash, compare_files, disassemble_file, etc.) se mantienen iguales

def plagiarism_checker(project_dir, comparison_dir):
    """Comprueba la similitud entre ejecutables en dos directorios específicos."""
    project_files = find_executable_files(project_dir)
    comparison_files = find_executable_files(compari42_Plagiarism_Checker/PD_push_swap/src/push_swap.pyson_dir)

    if not project_files:
        print("No se encontraron archivos ejecutables en la carpeta de proyectos.")
        return
    if not comparison_files:
        print("No se encontraron archivos ejecutables en la carpeta de comparación.")
        return

    # Matrices de similitud para comparación por bytes y por lógica
    byte_similarity_matrix = np.zeros((len(project_files), len(comparison_files)))
    logical_similarity_matrix = np.zeros((len(project_files), len(comparison_files)))

    for i, project_file in enumerate(project_files):
        for j, comparison_file in enumerate(comparison_files):
            # Comparación por bytes
            byte_similarity = compare_files(project_file, comparison_file)
            byte_similarity_matrix[i, j] = byte_similarity

            # Desensamblado y comparación lógica
            project_instructions = disassemble_file(project_file)
            comparison_instructions = disassemble_file(comparison_file)
            logical_similarity = compare_instructions(project_instructions, comparison_instructions)
            logical_similarity_matrix[i, j] = logical_similarity

            # Extrae el número del nombre del archivo de comparación
            repo_name = os.path.basename(comparison_file)
            repo_number = ''.join(filter(str.isdigit, repo_name))
            repo_display_name = get_repo_name(repo_number)
            
            # Asigna colores a las similitudes y los muestra
            byte_color = get_color_for_similarity(byte_similarity)
            logical_color = get_color_for_similarity(logical_similarity)

            print(f"\nSimilitud con {repo_display_name} (push_swap_C{repo_number}):\n")
            print(f"\n*Bytes map similarity: {byte_color}{byte_similarity:.2f}%{reset_color()}\n")
            print(f"*Logical Similarity: {logical_color}{logical_similarity:.2f}%{reset_color()}\n")

    # Generación de heatmaps
    generate_heatmap(byte_similarity_matrix, project_files, comparison_files, 
                     "Mapa de Calor de Similitud de Bytes", "byte_similarity_heatmap.png")
    generate_heatmap(logical_similarity_matrix, project_files, comparison_files, 
                     "Mapa de Calor de Similitud Lógica", "logical_similarity_heatmap.png")

# Código de inicio del programa
if __name__ == "__main__":
    project_dir = '../TARGET_DIR'  # Ruta relativa a TARGET_DIR desde PD_push_swap
    comparison_dir = 'ph_philo_comparative'

    # Verifica si la ruta existe
    full_path = os.path.abspath(project_dir)
    if os.path.exists(full_path):
        plagiarism_checker(full_path, comparison_dir)
    else:
        print(f"La ruta {full_path} no existe.")