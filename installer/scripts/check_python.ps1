# Check if Python is installed and meets minimum version requirement
# Returns exit code 0 if OK, 1 if not found or too old

$MinimumVersion = [Version]"3.11.0"
$ErrorActionPreference = "Stop"

# Function to check a specific Python command
function Test-PythonCommand {
    param([string]$Command)

    try {
        $output = & $Command --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $versionMatch = $output | Select-String -Pattern "Python (\d+\.\d+\.\d+)"
            if ($versionMatch) {
                return $versionMatch.Matches.Groups[1].Value
            }
        }
    }
    catch {
        # Command not found or failed
    }
    return $null
}

# Try different Python commands (py launcher first as it finds the latest version)
$pythonCommands = @("py", "python", "python3")
$foundVersion = $null
$foundCommand = $null

foreach ($cmd in $pythonCommands) {
    $ver = Test-PythonCommand -Command $cmd
    if ($ver) {
        $foundVersion = $ver
        $foundCommand = $cmd
        break
    }
}

if (-not $foundVersion) {
    Write-Host "ERROR: Python not found in PATH"
    Write-Host ""
    Write-Host "Please install Python 3.11 or higher from:"
    Write-Host "https://www.python.org/downloads/"
    Write-Host ""
    Write-Host "Make sure to check 'Add Python to PATH' during installation!"
    exit 1
}

# Check version
$version = [Version]$foundVersion

if ($version -ge $MinimumVersion) {
    Write-Host "SUCCESS: Python $foundVersion found via '$foundCommand' command"
    exit 0
}
else {
    Write-Host "ERROR: Python $foundVersion found but version is too old"
    Write-Host ""
    Write-Host "Required: Python $MinimumVersion or higher"
    Write-Host "Found:    Python $foundVersion"
    Write-Host ""
    Write-Host "Please upgrade Python from:"
    Write-Host "https://www.python.org/downloads/"
    exit 1
}
