# Python Detection Fix

## Problem

The installer was failing to detect Python 3.14.1 even though it was installed and in PATH.

## Root Cause

Windows systems can have multiple Python installations with different commands:
- `python` - May point to older Python versions
- `python3` - Alternative command for Python 3.x
- `py` - **Windows Python Launcher** - Always finds the latest installed Python version

In your case:
- `python` → Python 3.10.9 (too old)
- `python3` → Python 3.10.11 (too old)
- `py` → Python 3.14.1 ✅ (correct version!)

The installer was checking `python` first, which found the old version.

## Solution

### 1. Updated `installer\scripts\check_python.ps1`

**Changes:**
- Reordered Python command detection to check `py` **first** (instead of last)
- Added better error messages with specific version information
- Improved detection logic to try multiple commands

**Before:**
```powershell
$pythonCommands = @("python", "python3", "py")  # Wrong order!
```

**After:**
```powershell
$pythonCommands = @("py", "python", "python3")  # Correct order!
```

### 2. Updated `installer\dns-tunnel-detection.iss`

**Changes:**
- Added `GetPythonCommand()` function to detect the correct Python command
- Added global `PythonCommand` variable to store the detected command
- Updated all Python-related functions to use the detected command:
  - `CheckPython()` - Now stores detected command
  - `InstallDependencies()` - Uses `PythonCommand` instead of hardcoded `python`
  - `TrainModel()` - Uses `PythonCommand` instead of hardcoded `python`
  - `InstallService()` - Uses `PythonCommand` for NSSM service setup

**Before:**
```pascal
PipCommand := 'python -m pip install -r "' + ...  // Hardcoded!
```

**After:**
```pascal
PipCommand := PythonCommand + ' -m pip install -r "' + ...  // Dynamic!
```

## What Changed

### Files Modified

1. **`installer\scripts\check_python.ps1`**
   - Line 27: Reordered Python commands (py first)
   - Lines 8-24: Added `Test-PythonCommand` function
   - Lines 40-66: Enhanced error messages

2. **`installer\dns-tunnel-detection.iss`**
   - Line 124: Added `PythonCommand` variable
   - Lines 127-154: Added `GetPythonCommand()` function
   - Lines 157-189: Enhanced `CheckPython()` function
   - Line 410: Updated `InstallDependencies()` to use `PythonCommand`
   - Line 437: Updated `TrainModel()` to use `PythonCommand`
   - Lines 456-510: Updated `InstallService()` to use `PythonCommand`

## How It Works Now

### Detection Flow

1. **PowerShell Script** (`check_python.ps1`):
   ```
   Try 'py' command first → Found Python 3.14.1 ✅
   ```

2. **InnoSetup Wizard**:
   ```
   Run check_python.ps1 → Success
   Call GetPythonCommand() → Returns "py"
   Store in PythonCommand variable → "py"
   ```

3. **All Python Operations**:
   ```
   pip install → Uses "py -m pip install ..."
   Train model → Uses "py train_model.py ..."
   Install service → Uses "py" as executable
   ```

## Testing

### Test the PowerShell Script

```powershell
# Test directly
powershell -ExecutionPolicy Bypass -File installer\scripts\check_python.ps1
```

**Expected Output:**
```
SUCCESS: Python 3.14.1 found via 'py' command
```

### Test Full Installer

1. Compile installer:
   ```cmd
   iscc installer\dns-tunnel-detection.iss
   ```

2. Run installer:
   ```cmd
   installer\output\DNSTunnelDetection-Setup-1.0.0.exe
   ```

3. Check installer log (if there are issues):
   ```
   C:\Users\<username>\AppData\Local\Temp\Setup Log YYYY-MM-DD #XXX.txt
   ```

## Why This Fix Works

### Windows Python Launcher (`py`)

The `py` command is the **Windows Python Launcher** which:
- ✅ Automatically finds the latest Python version
- ✅ Respects `py.ini` configuration
- ✅ Handles multiple Python installations correctly
- ✅ Is the recommended way to run Python on Windows

### Command Priority

By checking `py` first, we ensure:
1. Latest Python version is found
2. User's preferred Python installation is used
3. Fallback to `python` or `python3` if `py` is not available
4. Compatible with all Windows Python installations

## Verification Checklist

After installing, verify:

- ✅ Installer detects Python 3.14.1
- ✅ Dependencies install successfully
- ✅ Model training completes
- ✅ Windows Service is created with correct Python path
- ✅ Service starts and runs properly

## Common Python Commands on Windows

| Command | What It Finds | Your System |
|---------|---------------|-------------|
| `py` | Latest Python via launcher | 3.14.1 ✅ |
| `python` | First `python.exe` in PATH | 3.10.9 ❌ |
| `python3` | First `python3.exe` in PATH | 3.10.11 ❌ |
| `py -3.14` | Specific version | 3.14.1 ✅ |

## Recommendations

### For Users

1. **Always use `py` command** on Windows (not `python`)
2. Install Python with "Add to PATH" option checked
3. Keep only one Python version if possible (or use virtual environments)

### For Developers

1. Use `py` launcher in scripts for Windows
2. Test with multiple Python installations
3. Always check which Python is being used in logs

## Additional Improvements Made

1. **Better Error Messages**: Now shows exact version found vs. required
2. **Detailed Logging**: All Python operations log the command used
3. **Robust Detection**: Tries multiple commands before giving up
4. **Clear Instructions**: Error messages include download links and steps

## Rollback

If you need to revert these changes:

```bash
git checkout HEAD installer/scripts/check_python.ps1
git checkout HEAD installer/dns-tunnel-detection.iss
```

## Status

✅ **FIXED** - Installer now correctly detects Python 3.14.1 via the `py` launcher.

---

**Fix Date**: 2025-12-04
**Issue**: Installer couldn't find Python 3.14.1
**Solution**: Prioritize Windows Python Launcher (`py` command)
