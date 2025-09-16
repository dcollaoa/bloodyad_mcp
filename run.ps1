#!/usr/bin/env powershell

Write-Host "Building Docker image..."
docker build -t bloodyad-assistant-mcp-server .

Write-Host "Automation script finished."
