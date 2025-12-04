# Install DNS Tunnel Detection Service using NSSM
# This script is called by InnoSetup installer

param(
    [string]$InstallPath,
    [string]$ServiceName = "DNSTunnelDetection"
)

Write-Host "Installing Windows Service: $ServiceName"
Write-Host "Install Path: $InstallPath"

# Find Python executable
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonCmd) {
    Write-Error "Python not found in PATH"
    exit 1
}

$pythonExe = $pythonCmd.Source
Write-Host "Python: $pythonExe"

# NSSM path
$nssmExe = Join-Path $InstallPath "bin\nssm.exe"
$serviceScript = Join-Path $InstallPath "service\dns_tunnel_service.py"

# Install service
& $nssmExe install $ServiceName $pythonExe $serviceScript

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Service installed successfully"
    
    # Configure service
    & $nssmExe set $ServiceName AppDirectory $InstallPath
    & $nssmExe set $ServiceName DisplayName "DNS Tunnel Detection Service"
    & $nssmExe set $ServiceName Description "Enterprise DNS tunneling detection and alerting system"
    & $nssmExe set $ServiceName Start SERVICE_AUTO_START
    
    Write-Host "✓ Service configured"
    exit 0
} else {
    Write-Error "Failed to install service"
    exit 1
}
