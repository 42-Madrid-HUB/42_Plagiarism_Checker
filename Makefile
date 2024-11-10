# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: ismherna <ismherna@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/11/04 13:30:41 by ismherna          #+#    #+#              #
#    Updated: 2024/11/07 21:18:39 by ismherna         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

# Colors
GREEN = \033[1;32m
CYAN = \033[1;36m
YELLOW = \033[1;33m
RED = \033[0;31m
RESET = \033[0m

# Available projects
PROJECTS = PD_Fract_ol PD_Get_next_line PD_Pipex PD_So_Long PD_fdf PD_minitalk PD_push_swap PD_DEBUG

# Main target
all: banner help

# Display a large banner
banner:
	@echo "$(RED) #******************************************************************************************************************************************************************************#$(RESET)"
	@echo "$(RED) #                                                                                                                                                                        #$(RESET)"
	@echo "$(RED) #  ██╗  ██╗██████╗     ██████╗ ██╗      █████╗  ██████╗ ██╗ █████╗ ██████╗ ██╗███████╗███╗   ███╗    ██████╗ ███████╗████████╗███████╗ ██████╗████████╗ ██████╗ ██████╗  	#$(RESET)"
	@echo "$(RED) #  ██║  ██║╚════██╗    ██╔══██╗██║     ██╔══██╗██╔════╝ ██║██╔══██╗██╔══██╗██║██╔════╝████╗ ████║    ██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗ 	#$(RESET)"
	@echo "$(RED) #  ███████║ █████╔╝    ██████╔╝██║     ███████║██║  ███╗██║███████║██████╔╝██║███████╗██╔████╔██║    ██║  ██║█████╗     ██║   █████╗  ██║        ██║   ██║   ██║██████╔╝ 	#$(RESET)"
	@echo "$(RED) #  ╚════██║██╔═══╝     ██╔═══╝ ██║     ██╔══██║██║   ██║██║██╔══██║██╔══██╗██║╚════██║██║╚██╔╝██║    ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗ 	#$(RESET)"
	@echo "$(RED) #       ██║███████╗    ██║     ███████╗██║  ██║╚██████╔╝██║██║  ██║██║  ██║██║███████║██║ ╚═╝ ██║    ██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║ 	#$(RESET)"
	@echo "$(RED) #       ╚═╝╚══════╝    ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝    ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ 	#$(RESET)" 
	@echo "$(RED) #                                                                                                                                                                              #$(RESET)"                                                                                                                                                           	
	@echo "$(RED) #******************************************************************************************************************************************************************************#$(RESET)"
	@echo "$(RESET)"


# Regla para instalar dependencias de Python
install-deps:
	@echo "Instalando dependencias de Python..."
	@pip install numpy matplotlib capstone

# El resto de tu Makefile sigue igual...

# Define a target for each project
$(PROJECTS):
	@echo "$(CYAN)Running project $(YELLOW)$@$(RESET)"
	@cd $@ && python3 src/$(shell echo $@ | sed 's/^PD_//').py
	@echo "$(CYAN)Finished running $(YELLOW)$@$(RESET)"

# Help message
help:
	@echo "$(CYAN)Usage: make <project>$(RESET)"
	@echo "$(GREEN)Available projects:$(RESET)"
	@for project in $(PROJECTS); do \
		echo "  - $(YELLOW)$$project$(RESET)"; \
	done

# Clean up output files
clean:
	@echo -e "$(RED)Cleaning up generated output files$(RESET)"
	@rm -rf output

# Phony targets
.PHONY: all $(PROJECTS) banner help clean