# Check if Python is installed and meets minimum version requirement
# Returns exit code 0 if OK, 1 if not found or too old

$MinimumVersion = [Version]"3.11.0"

try {
    # Try to get Python version
    $pythonVersion = & python --version 2>&1 | Select-String -Pattern "Python (\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches.Groups[1].Value }

    if ($pythonVersion) {
        $version = [Version]$pythonVersion

        if ($version -ge $MinimumVersion) {
            Write-Host "Python $pythonVersion found (minimum: $MinimumVersion) - OK"
            exit 0
        }
        else {
            Write-Host "Python $pythonVersion found but too old (minimum: $MinimumVersion)"
            exit 1
        }
    }
    else {
        Write-Host "Python not found in PATH"
        exit 1
    }
}
catch {
    Write-Host "Error checking Python: $_"
    exit 1
}
