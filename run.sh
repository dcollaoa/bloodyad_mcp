#!/bin/bash

# --------------------------- UI/UX STYLE DEFINITIONS --------------------------- 
# ANSI color codes
COLOR_STEP="\033[0;36m"    # Cyan
COLOR_SUCCESS="\033[0;32m" # Green
COLOR_WARN="\033[0;33m"    # Yellow
COLOR_ERROR="\033[0;31m"   # Red
COLOR_INFO="\033[0;90m"    # Gray
COLOR_BORDER="\033[0;37m"  # White (using white for border as dark gray might be hard to see)
COLOR_RESET="\033[0m"     # Reset to default

# --- Helper functions for clean output ---
write_step() {
    echo -e "\n${COLOR_STEP}--- $1 ---${COLOR_RESET}"
}

write_status() {
    local message="$1"
    local status="${2:-Success}" # Default to Success

    local color=""
    case "$status" in
        "Success") color="${COLOR_SUCCESS}" ;; 
        "Warning") color="${COLOR_WARN}" ;; 
        "Failed")  color="${COLOR_ERROR}" ;; 
        "Info")    color="${COLOR_INFO}" ;; 
        *)         color="${COLOR_RESET}" ;; 
    esac
    echo -e "${color}> ${status}: ${message}${COLOR_RESET}"
}

show_banner() {
    local banner_text="bloodyAD MCP Server Setup"
    local line=$(printf \"=%%.0s\" $(seq 1 $(( ${#banner_text} + 4 ))))
    echo ""
    echo -e "${COLOR_WARN}${line}${COLOR_RESET}"
    echo -e "${COLOR_WARN}  ${banner_text}  ${COLOR_RESET}"
    echo -e "${COLOR_WARN}${line}${COLOR_RESET}"
    echo ""
}

# --------------------------- SCRIPT LOGIC --------------------------- 

invoke_docker_setup() {
    write_step "Step 1: Building Docker image"
    docker build -t bloodyad-mcp .
    if [ $? -ne 0 ]; then
        write_status "Docker build failed. Exiting." "Failed"
        exit 1
    fi
    write_status "Docker image 'bloodyad-mcp' built successfully."

    read -p "> Do you want to run a container for an interactive test? (y/N) " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        write_status "Starting container. Type 'exit' to continue the script." "Info"
        docker run --rm -it bloodyad-mcp /bin/bash
    fi
}

set_mcp_configuration() {
    write_step "Step 2: Configuring MCP catalog and registry"
    local mcp_root="${HOME}/.docker/mcp"
    local catalogs_dir="${mcp_root}/catalogs"
    local custom_yaml_src="$(dirname "$0")"/custom.yaml
    local custom_yaml_dst="${catalogs_dir}/custom.yaml"
    local registry_yaml="${mcp_root}/registry.yaml"

    if [ ! -d "$catalogs_dir" ]; then
        mkdir -p "$catalogs_dir"
        write_status "Created MCP catalogs directory at '${catalogs_dir}'."
    fi

    if [ -f "$custom_yaml_dst" ]; then
        read -p "> 'custom.yaml' already exists. Do you want to overwrite it? (y/N) " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            cp "$custom_yaml_src" "$custom_yaml_dst"
            write_status "'custom.yaml' was overwritten."
        else
            write_status "Skipped overwriting 'custom.yaml'." "Warning"
        fi
    else
        cp "$custom_yaml_src" "$custom_yaml_dst"
        write_status "'custom.yaml' copied to destination."
    fi

    local registry_yaml_src="$(dirname "$0")"/registry.yaml # Source registry.yaml from project
    local registry_yaml_dst="${mcp_root}/registry.yaml" # Destination registry.yaml on host

    # Define the bloodyad-mcp entry to be inserted
    # Extracting the specific lines from the project's registry.yaml
    BLOODYAD_MCP_ENTRY=$(awk '
/^  bloodyad-mcp:/ {
    print $0;
    found = 1;
    next;
}
found && /^    / {
    print $0;
    next;
}
found && !/^    / {
    found = 0;
}
' "${registry_yaml_src}")

    if [ ! -f "$registry_yaml_dst" ]; then
        cp "${registry_yaml_src}" "${registry_yaml_dst}"
        write_status "'registry.yaml' copied to destination as it did not exist."
    else
        if grep -q "bloodyad-mcp:" "$registry_yaml_dst"; then
            write_status "Entry for 'bloodyad-mcp' already exists in registry.yaml." "Warning"
        else
            if ! grep -q "^registry:" "$registry_yaml_dst"; then
                cp "${registry_yaml_src}" "${registry_yaml_dst}"
                write_status "'registry.yaml' was empty or invalid and has been overwritten."
            else
                echo "" >> "$registry_yaml_dst"
                echo "${BLOODYAD_MCP_ENTRY}" >> "$registry_yaml_dst"
                write_status "'bloodyad-mcp' entry added to existing registry.yaml."
            fi
        fi
    fi
}

update_gemini_settings() {
    write_step "Step 3: Updating Gemini settings.json"
    
    local settings_path="${HOME}/.gemini/settings.json"
    
    if [ ! -f "$settings_path" ]; then
        write_status "Could not find 'settings.json' at '${settings_path}'." "Warning"
        write_status "Please create the file first or add the config block manually." "Info"
        show_settings_json_sample
        return
    fi

    if ! command -v jq &> /dev/null; then
        write_status "jq is not installed. Please install it to update settings.json." "Failed"
        write_status "On Debian/Ubuntu: sudo apt-get install jq" "Info"
        write_status "On Fedora: sudo dnf install jq" "Info"
        write_status "On Arch Linux: sudo pacman -S jq" "Info"
        show_settings_json_sample
        return
    fi

    local backup_path="${settings_path}.bak"
    cp "$settings_path" "$backup_path"
    write_status "Backup of settings.json created at '${backup_path}'." "Info"

    local mcp_path="${HOME}/.docker/mcp"
    
    local mcp_gateway_json=$(jq -n \
        --arg mcp_path "$mcp_path" \
        '{ 
            command: "docker",
            args: [
                "run", "-i", "--rm",
                "-v", "//var/run/docker.sock:/var/run/docker.sock",
                "-v", ($mcp_path + ":/mcp"),
                "docker/mcp-gateway",
                "--catalog=/mcp/catalogs/custom.yaml",
                "--config=/mcp/config.yaml",
                "--registry=/mcp/registry.yaml",
                "--tools-config=/mcp/tools.yaml",
                "--transport=stdio"
            ]
        }')

    if ! jq --argjson gateway "$mcp_gateway_json" 
            '.mcpServers = (.mcpServers // {}) | .mcpServers["mcp-toolkit-gateway"] = $gateway' \
            "$settings_path" > "$settings_path.tmp"; then
        write_status "An error occurred while updating settings.json." "Failed"
        write_status "Your backup has been restored." "Warning"
        cp "$backup_path" "$settings_path"
        show_settings_json_sample
        return
    fi
    mv "$settings_path.tmp" "$settings_path"
    write_status "settings.json was updated safely!"
}

show_settings_json_sample() {
    local user=$(whoami)
    local mcp_path="/home/${user}/.docker/mcp" # Assuming /home/user for Linux
    local sample_settings=$(cat <<EOF
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "//var/run/docker.sock:/var/run/docker.sock",
        "-v", "${mcp_path}:/mcp",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
EOF
)
    local border=$(printf -- "-%.0s" $(seq 1 60))
    echo -e "\n${COLOR_INFO}This is an example of what needs to be in your settings.json:${COLOR_RESET}"
    echo -e "${COLOR_BORDER}${border}${COLOR_RESET}"
    echo -e "${COLOR_INFO}${sample_settings}${COLOR_RESET}"
    echo -e "${COLOR_BORDER}${border}${COLOR_RESET}"
}

invoke_gemini_prompt() {
    write_step "Step 4: Run Gemini"
    read -p "> Do you want to run 'gemini lets use bloodyad!' now? (y/N) " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        write_status "Executing command..." "Info"
        gemini lets use bloodyad!
    fi
}


# --------------------------- SCRIPT EXECUTION --------------------------- 
show_banner
invoke_docker_setup
set_mcp_configuration
update_gemini_settings
invoke_gemini_prompt

write_step "Step 5: All done!"
write_status "The environment for the bloodyAD MCP Server is ready."
echo ""
