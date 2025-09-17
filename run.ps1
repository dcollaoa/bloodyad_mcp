<#
    .SYNOPSIS
        script to automate the setup for the bloodyAD MCP Server with GEMINI-CLI.
    .DESCRIPTION
        This script guides the user through building the Docker image,
        configuring MCP files, safely updating only the required key in the 
        Gemini settings.json file, and finally prompts to run Gemini.
    .AUTHOR
        3ky
#>

[CmdletBinding()]
param()

# --------------------------- UI/UX STYLE DEFINITIONS ---------------------------
$Global:Theme = @{
    Step    = "Cyan"
    Success = "Green"
    Warn    = "Yellow"
    Error   = "Red"
    Info    = "Gray"
    Border  = "DarkGray"
}

# --- Helper functions for clean output ---
function Write-Step {
    param($Message)
    Write-Host "`n"
    Write-Host "--- $Message ---" -ForegroundColor $Global:Theme.Step
}

function Write-Status {
    param(
        $Message,
        [ValidateSet('Success', 'Warning', 'Failed', 'Info')]
        $Status = 'Success'
    )
    $Color = switch ($Status) {
        'Success' { $Global:Theme.Success }
        'Warning' { $Global:Theme.Warn }
        'Failed'  { $Global:Theme.Error }
        'Info'    { $Global:Theme.Info }
    }
    Write-Host "> ${Status}: $Message" -ForegroundColor $Color
}

function Show-Banner {
    $BannerText = "bloodyAD MCP Server Setup"
    $Line = "=" * ($BannerText.Length + 4)
    Write-Host ""
    Write-Host $Line -ForegroundColor $Global:Theme.Warn
    Write-Host "  $BannerText  " -ForegroundColor $Global:Theme.Warn
    Write-Host $Line -ForegroundColor $Global:Theme.Warn
    Write-Host ""
}

# --------------------------- SCRIPT LOGIC ---------------------------

function Invoke-DockerSetup {
    Write-Step "Step 1: Building Docker image"
    docker build -t bloodyad-mcp .
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Docker build failed. Exiting." -Status 'Failed'
        exit 1
    }
    Write-Status "Docker image 'bloodyad-mcp' built successfully."

    $Choice = Read-Host "> Do you want to run a container for an interactive test? (y/N)"
    if ($Choice -eq 'y') {
        Write-Status "Starting container. Type 'exit' to continue the script." -Status 'Info'
        docker run --rm -it bloodyad-mcp /bin/bash
    }
}

function Set-McpConfiguration {
    Write-Step "Step 2: Configuring MCP catalog and registry"
    $McpRoot = Join-Path $env:USERPROFILE ".docker\mcp"
    $CatalogsDir = Join-Path $McpRoot "catalogs"
    $CustomYamlSrc = Join-Path $PSScriptRoot "custom.yaml"
    $CustomYamlDst = Join-Path $CatalogsDir "custom.yaml"
    $RegistryYaml = Join-Path $McpRoot "registry.yaml"

    if (-not (Test-Path $CatalogsDir)) {
        New-Item -ItemType Directory -Path $CatalogsDir -Force | Out-Null
        Write-Status "Created MCP catalogs directory at '$CatalogsDir'."
    }

    if (Test-Path $CustomYamlDst) {
        $Choice = Read-Host "> 'custom.yaml' already exists. Do you want to overwrite it? (y/N)"
        if ($Choice -eq 'y') {
            Copy-Item -Path $CustomYamlSrc -Destination $CustomYamlDst -Force
            Write-Status "'custom.yaml' was overwritten."
        }
        else {
            Write-Status "Skipped overwriting 'custom.yaml'." -Status 'Warning'
        }
    }
    else {
        Copy-Item -Path $CustomYamlSrc -Destination $CustomYamlDst -Force
        Write-Status "'custom.yaml' copied to destination."
    }

    $RegistryYamlSrc = Join-Path $PSScriptRoot "registry.yaml" # Source registry.yaml from project
    $RegistryYamlDst = Join-Path $McpRoot "registry.yaml" # Destination registry.yaml on host

    # Define the bloodyad-mcp entry to be inserted
    $ProjectRegistryContent = Get-Content $RegistryYamlSrc -Raw
    $BloodyAdMcpEntryMatch = $ProjectRegistryContent | Select-String -Pattern "(?m)^  bloodyad-mcp:\s*\n((?: {4}.*\n)*)" -AllMatches
    if ($BloodyAdMcpEntryMatch.Matches.Count -gt 0) {
        $BloodyAdMcpEntry = "  bloodyad-mcp:`n" + $BloodyAdMcpEntryMatch.Matches[0].Groups[1].Value.TrimEnd()
    } else {
        Write-Status "Error: Could not find 'bloodyad-mcp' entry in project's registry.yaml or regex failed to match." -Status 'Failed'
        exit 1
    }

    if (-not (Test-Path $RegistryYamlDst)) {
        Copy-Item -Path $RegistryYamlSrc -Destination $RegistryYamlDst -Force
        Write-Status "'registry.yaml' copied to destination as it did not exist."
    } else {
        $RegContent = Get-Content $RegistryYamlDst -Raw
        if ($RegContent -match 'bloodyad-mcp:') {
            Write-Status "Entry for 'bloodyad-mcp' already exists in registry.yaml." -Status 'Warning'
        } else {
            if (($RegContent.Trim() -eq "") -or ($RegContent -notmatch '^registry:')) {
                Copy-Item -Path $RegistryYamlSrc -Destination $RegistryYamlDst -Force
                Write-Status "'registry.yaml' was empty or invalid and has been overwritten."
            } else {
                Add-Content -Path $RegistryYamlDst -Value ("`n" + $BloodyAdMcpEntry)
                Write-Status "'bloodyad-mcp' entry added to existing registry.yaml."
            }
        }
    }
}

function Update-GeminiSettings {
    Write-Step "Step 3: Updating Gemini settings.json"
    
    $SettingsPath = Join-Path $env:USERPROFILE ".gemini\settings.json"
    
    if (-not (Test-Path $SettingsPath)) {
        Write-Status "Could not find 'settings.json' at '$SettingsPath'." -Status 'Warning'
        Write-Status "Please create the file first or add the config block manually." -Status 'Info'
        Show-SettingsJsonSample
        return
    }

    try {
        $BackupPath = "$SettingsPath.bak"
        Copy-Item -Path $SettingsPath -Destination $BackupPath -Force
        Write-Status "Backup of settings.json created at '$BackupPath'." -Status 'Info'

        $settings = Get-Content $SettingsPath -Raw | ConvertFrom-Json -ErrorAction Stop
        
        $McpPath = Join-Path $env:USERPROFILE ".docker\mcp"
        
        $mcpGateway = [ordered]@{
            command = "docker"
            args    = @(
                "run", "-i", "--rm",
                "-e", "NODE_NO_WARNINGS=1",
                "-v", "//var/run/docker.sock:/var/run/docker.sock",
                "-v", "${McpPath}:/mcp",
                "docker/mcp-gateway",
                "--catalog=/mcp/catalogs/custom.yaml",
                "--config=/mcp/config.yaml",
                "--registry=/mcp/registry.yaml",
                "--tools-config=/mcp/tools.yaml",
                "--transport=stdio"
            )
        }

        if (-not $settings.PSObject.Properties['mcpServers']) {
            $settings | Add-Member -MemberType NoteProperty -Name 'mcpServers' -Value (New-Object -TypeName PSObject)
        }
        
        $settings.mcpServers | Add-Member -MemberType NoteProperty -Name 'mcp-toolkit-gateway' -Value $mcpGateway -Force

        # Using -Compress to create a minified, single-line JSON with no extra whitespace. (TODO FIX IT)
        $jsonOutput = $settings | ConvertTo-Json -Depth 10 -Compress
        $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($SettingsPath, $jsonOutput, $utf8WithoutBom)

        Write-Status "settings.json was updated safely!"
    }
    catch {
        Write-Status "An error occurred while updating settings.json." -Status 'Failed'
        Write-Status $_.Exception.Message -Status 'Info'
        Write-Status "Your backup has been restored." -Status 'Warning'
        Copy-Item -Path $BackupPath -Destination $SettingsPath -Force
        Show-SettingsJsonSample
    }
}

function Show-SettingsJsonSample {
    $user = $env:USERNAME
    $McpPath = "C:\\Users\\$user\\.docker\\mcp"
    $SampleSettings = @"
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "//var/run/docker.sock:/var/run/docker.sock",
        "-v", "${McpPath}:/mcp",
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
"@
    $border = "-" * 60
    Write-Host "`n"
    Write-Host "This is an example of what needs to be in your settings.json:" -ForegroundColor $Global:Theme.Info
    Write-Host $border -ForegroundColor $Global:Theme.Border
    Write-Host $SampleSettings -ForegroundColor $Global:Theme.Info
    Write-Host $border -ForegroundColor $Global:Theme.Border
}

function Invoke-GeminiPrompt {
    Write-Step "Step 4: Run Gemini"
    $Choice = Read-Host "> Do you want to run 'gemini lets use bloodyad!' now? (y/N)"
    if ($Choice -eq 'y') {
        Write-Status "Executing command..." -Status 'Info'
        Invoke-Expression "gemini lets use bloodyad!"
    }
}


# --------------------------- SCRIPT EXECUTION ---------------------------
Show-Banner
Invoke-DockerSetup
Set-McpConfiguration
Update-GeminiSettings
Invoke-GeminiPrompt

Write-Step "Step 5: All done!"
Write-Status "The environment for the bloodyAD MCP Server is ready."
Write-Host ""