; DNS Tunnel Detection Service - InnoSetup Installer Script
; Creates professional Windows installer with GUI configuration wizard

#define MyAppName "DNS Tunnel Detection Service"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Organization"
#define MyAppURL "https://github.com/SandyK43/DnsTunnel"
#define MyAppExeName "dns_tunnel_service.py"
#define MyAppServiceName "DNSTunnelDetection"
#define MyAppServiceDisplayName "DNS Tunnel Detection Service"

[Setup]
; Basic application info
AppId={{A8B9C1D2-E3F4-5678-9ABC-DEF012345678}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\DNSTunnelDetection
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
InfoBeforeFile=..\installer\INSTALL_INFO.txt
OutputDir=..\installer\output
OutputBaseFilename=DNSTunnelDetection-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
; UninstallDisplayIcon={app}\icon.ico

; Visual customization (images optional - comment out if not available)
; WizardImageFile=..\installer\wizard-image.bmp
; WizardSmallImageFile=..\installer\wizard-small.bmp
; SetupIconFile=..\installer\setup-icon.ico

; Minimum Windows version
MinVersion=10.0.17763

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (recommended)"
Name: "minimal"; Description: "Minimal installation (API only, no dashboard)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Core detection service"; Types: full minimal custom; Flags: fixed
Name: "dashboard"; Description: "Streamlit demo dashboard"; Types: full
Name: "docs"; Description: "Documentation"; Types: full custom

[Files]
; Core application files
Source: "..\agents\*"; DestDir: "{app}\agents"; Flags: ignoreversion recursesubdirs; Components: core
Source: "..\api\*"; DestDir: "{app}\api"; Flags: ignoreversion recursesubdirs; Components: core
Source: "..\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs; Components: core
Source: "..\scripts\*"; DestDir: "{app}\scripts"; Flags: ignoreversion recursesubdirs; Components: core
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "..\config.example.yaml"; DestDir: "{app}"; Flags: ignoreversion; Components: core

; Dashboard
Source: "..\demo\*"; DestDir: "{app}\demo"; Flags: ignoreversion recursesubdirs; Components: dashboard


; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs
Source: "..\SETUP_README.md"; DestDir: "{app}"; Flags: ignoreversion; Components: docs

; Note: Data directories are created via [Dirs] section below (no files needed)

; Installer helper scripts
Source: "..\installer\scripts\check_python.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "..\installer\scripts\install_service.ps1"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "..\installer\scripts\configure.py"; DestDir: "{tmp}"; Flags: deleteafterinstall

; NSSM for service installation
Source: "..\installer\nssm\nssm.exe"; DestDir: "{app}\bin"; Flags: ignoreversion; Components: core

[Dirs]
Name: "{app}\models"; Permissions: users-modify
Name: "{app}\data"; Permissions: users-modify
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\reports"; Permissions: users-modify
Name: "{commonappdata}\DNSTunnelDetection"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "http://localhost:8000/docs"; Comment: "Open API Documentation"
Name: "{group}\Dashboard"; Filename: "http://localhost:8501"; Comment: "Open Demo Dashboard"; Components: dashboard
Name: "{group}\Configuration"; Filename: "{app}\config.yaml"; Comment: "Edit Configuration"
Name: "{group}\Logs"; Filename: "{app}\logs"; Comment: "View Service Logs"
Name: "{group}\Setup Guide"; Filename: "{app}\SETUP_README.md"; Comment: "View Setup Instructions"; Components: docs
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Registry]
; Register application
Root: HKLM; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"
Root: HKLM; Subkey: "Software\{#MyAppPublisher}\{#MyAppName}"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"

[Code]
var
  ConfigPage: TInputQueryWizardPage;
  ThresholdPage: TInputQueryWizardPage;
  AlertingPage: TInputQueryWizardPage;
  DatabasePage: TInputOptionWizardPage;

  PythonPath: String;
  PythonVersion: String;

{ Check if Python is installed and meets minimum version requirement }
function CheckPython(): Boolean;
var
  ResultCode: Integer;
  PythonCheckOutput: AnsiString;
begin
  Result := False;

  // Try to find Python
  if Exec('powershell.exe', '-ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\check_python.ps1') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      Result := True;
      Log('Python found and version is acceptable');
    end
    else
    begin
      Log('Python not found or version too old');
      MsgBox('Python 3.11 or higher is required but not found.' + #13#10 + #13#10 +
             'Please install Python from https://www.python.org/downloads/' + #13#10 +
             'Make sure to check "Add Python to PATH" during installation.',
             mbError, MB_OK);
    end;
  end;
end;

{ Initialize wizard pages }
procedure InitializeWizard;
begin
  // Database selection page
  DatabasePage := CreateInputOptionWizardPage(wpSelectComponents,
    'Database Configuration', 'Choose your database backend',
    'Select which database to use for storing DNS queries and alerts.',
    True, False);
  DatabasePage.Add('SQLite (Embedded) - Recommended for small/medium deployments');
  DatabasePage.Add('PostgreSQL (External) - Recommended for enterprise deployments');
  DatabasePage.Values[0] := True;

  // Detection thresholds page
  ThresholdPage := CreateInputQueryWizardPage(DatabasePage.ID,
    'Detection Configuration', 'Configure detection sensitivity',
    'Set thresholds for alert triggering. Lower values = more sensitive.');
  ThresholdPage.Add('Suspicious threshold (0.0-1.0):', False);
  ThresholdPage.Add('High severity threshold (0.0-1.0):', False);
  ThresholdPage.Values[0] := '0.70';
  ThresholdPage.Values[1] := '0.85';

  // Alerting configuration page
  AlertingPage := CreateInputQueryWizardPage(ThresholdPage.ID,
    'Alerting Configuration', 'Configure alert notifications',
    'Enter webhook URLs and email settings for receiving alerts.');
  AlertingPage.Add('Slack webhook URL (optional):', False);
  AlertingPage.Add('Email recipient (optional):', False);
  AlertingPage.Add('SMTP server (optional):', False);
  AlertingPage.Values[0] := '';
  AlertingPage.Values[1] := '';
  AlertingPage.Values[2] := 'smtp.gmail.com';

  // API configuration page
  ConfigPage := CreateInputQueryWizardPage(AlertingPage.ID,
    'API Configuration', 'Configure REST API settings',
    'Set the host and port for the REST API endpoint.');
  ConfigPage.Add('API Host:', False);
  ConfigPage.Add('API Port:', False);
  ConfigPage.Values[0] := '0.0.0.0';
  ConfigPage.Values[1] := '8000';
end;

{ Validate configuration inputs }
function NextButtonClick(CurPageID: Integer): Boolean;
var
  ThresholdSusp, ThresholdHigh: Extended;
  Port: Integer;
begin
  Result := True;

  // Validate threshold page
  if CurPageID = ThresholdPage.ID then
  begin
    if not TryStrToFloat(ThresholdPage.Values[0], ThresholdSusp) or
       (ThresholdSusp < 0.0) or (ThresholdSusp > 1.0) then
    begin
      MsgBox('Suspicious threshold must be between 0.0 and 1.0', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if not TryStrToFloat(ThresholdPage.Values[1], ThresholdHigh) or
       (ThresholdHigh < 0.0) or (ThresholdHigh > 1.0) then
    begin
      MsgBox('High threshold must be between 0.0 and 1.0', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    if ThresholdHigh <= ThresholdSusp then
    begin
      MsgBox('High threshold must be greater than suspicious threshold', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Validate config page
  if CurPageID = ConfigPage.ID then
  begin
    if not TryStrToInt(ConfigPage.Values[1], Port) or (Port < 1) or (Port > 65535) then
    begin
      MsgBox('Port must be between 1 and 65535', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
end;

{ Generate configuration file from wizard inputs }
procedure GenerateConfigFile();
var
  ConfigFile: String;
  ConfigContent: TStringList;
  DatabaseType: String;
begin
  ConfigFile := ExpandConstant('{app}\config.yaml');
  ConfigContent := TStringList.Create;

  try
    // Determine database type
    if DatabasePage.Values[0] then
      DatabaseType := 'sqlite'
    else
      DatabaseType := 'postgresql';

    // Build configuration
    ConfigContent.Add('# DNS Tunnel Detection Service Configuration');
    ConfigContent.Add('# Generated by installer on ' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', '-', ':'));
    ConfigContent.Add('');
    ConfigContent.Add('detection:');
    ConfigContent.Add('  threshold_suspicious: ' + ThresholdPage.Values[0]);
    ConfigContent.Add('  threshold_high: ' + ThresholdPage.Values[1]);
    ConfigContent.Add('  window_size: 60');
    ConfigContent.Add('  model_path: models/isolation_forest.pkl');
    ConfigContent.Add('');
    ConfigContent.Add('adaptive_thresholds:');
    ConfigContent.Add('  enabled: true');
    ConfigContent.Add('  target_fp_rate: 0.03');
    ConfigContent.Add('  max_fp_rate: 0.10');
    ConfigContent.Add('  min_fp_rate: 0.01');
    ConfigContent.Add('  adjustment_increment: 0.02');
    ConfigContent.Add('  min_samples_for_adjustment: 100');
    ConfigContent.Add('  check_interval_minutes: 60');
    ConfigContent.Add('  max_adjustment_frequency_hours: 6');
    ConfigContent.Add('  evaluation_window_hours: 24');
    ConfigContent.Add('');
    ConfigContent.Add('database:');
    ConfigContent.Add('  type: ' + DatabaseType);
    if DatabaseType = 'sqlite' then
    begin
      ConfigContent.Add('  path: data/dns_tunnel.db');
    end
    else
    begin
      ConfigContent.Add('  host: localhost');
      ConfigContent.Add('  port: 5432');
      ConfigContent.Add('  database: dns_tunnel_db');
      ConfigContent.Add('  username: dnsadmin');
      ConfigContent.Add('  password: changeme123');
    end;
    ConfigContent.Add('');
    ConfigContent.Add('alerting:');
    ConfigContent.Add('  throttle_seconds: 300');
    ConfigContent.Add('  slack:');
    if AlertingPage.Values[0] <> '' then
    begin
      ConfigContent.Add('    enabled: true');
      ConfigContent.Add('    webhook_url: ' + AlertingPage.Values[0]);
    end
    else
    begin
      ConfigContent.Add('    enabled: false');
    end;
    ConfigContent.Add('  email:');
    if AlertingPage.Values[1] <> '' then
    begin
      ConfigContent.Add('    enabled: true');
      ConfigContent.Add('    smtp_host: ' + AlertingPage.Values[2]);
      ConfigContent.Add('    smtp_port: 587');
      ConfigContent.Add('    from_address: alerts@company.com');
      ConfigContent.Add('    to_addresses: ' + AlertingPage.Values[1]);
      ConfigContent.Add('    username: your-email@gmail.com');
      ConfigContent.Add('    password: your-password');
    end
    else
    begin
      ConfigContent.Add('    enabled: false');
    end;
    ConfigContent.Add('  jira:');
    ConfigContent.Add('    enabled: false');
    ConfigContent.Add('');
    ConfigContent.Add('response:');
    ConfigContent.Add('  auto_block: false');
    ConfigContent.Add('  require_manual_approval: true');
    ConfigContent.Add('');
    ConfigContent.Add('collector:');
    ConfigContent.Add('  enabled: false');
    ConfigContent.Add('  sources: []');
    ConfigContent.Add('');
    ConfigContent.Add('api:');
    ConfigContent.Add('  host: ' + ConfigPage.Values[0]);
    ConfigContent.Add('  port: ' + ConfigPage.Values[1]);

    // Save configuration
    ConfigContent.SaveToFile(ConfigFile);
    Log('Configuration file created: ' + ConfigFile);
  finally
    ConfigContent.Free;
  end;
end;

{ Install Python dependencies }
function InstallDependencies(): Boolean;
var
  ResultCode: Integer;
  PipCommand: String;
begin
  Result := False;

  PipCommand := 'python -m pip install -r "' + ExpandConstant('{app}\requirements.txt') + '"';

  if Exec('cmd.exe', '/c ' + PipCommand, ExpandConstant('{app}'), SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      Result := True;
      Log('Dependencies installed successfully');
    end
    else
    begin
      Log('Failed to install dependencies, exit code: ' + IntToStr(ResultCode));
      MsgBox('Failed to install Python dependencies. Please run manually:' + #13#10 +
             'pip install -r requirements.txt', mbError, MB_OK);
    end;
  end;
end;

{ Train initial ML model }
function TrainModel(): Boolean;
var
  ResultCode: Integer;
  TrainCommand: String;
begin
  Result := False;

  TrainCommand := 'python "' + ExpandConstant('{app}\scripts\train_model.py') + '" --format sample --num-samples 5000';

  if Exec('cmd.exe', '/c ' + TrainCommand, ExpandConstant('{app}'), SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      Result := True;
      Log('Model trained successfully');
    end
    else
    begin
      Log('Failed to train model, exit code: ' + IntToStr(ResultCode));
      MsgBox('Failed to train ML model. You can train it manually later.', mbInformation, MB_OK);
      Result := True; // Don't fail installation
    end;
  end;
end;

{ Install Windows Service using NSSM }
function InstallService(): Boolean;
var
  ResultCode: Integer;
  NSSMPath, PythonExe, ServiceScript: String;
begin
  Result := False;

  NSSMPath := ExpandConstant('{app}\bin\nssm.exe');
  ServiceScript := ExpandConstant('{app}\service\dns_tunnel_service.py');

  // Find Python executable
  if Exec('cmd.exe', '/c where python', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    PythonExe := 'python'; // Use python from PATH
  end;

  // Install service
  if Exec(NSSMPath, 'install {#MyAppServiceName} "' + PythonExe + '" "' + ServiceScript + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
    begin
      // Configure service
      Exec(NSSMPath, 'set {#MyAppServiceName} AppDirectory "' + ExpandConstant('{app}') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(NSSMPath, 'set {#MyAppServiceName} DisplayName "{#MyAppServiceDisplayName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(NSSMPath, 'set {#MyAppServiceName} Description "Enterprise DNS tunneling detection and alerting system"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(NSSMPath, 'set {#MyAppServiceName} Start SERVICE_AUTO_START', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

      Result := True;
      Log('Service installed successfully');
    end
    else
    begin
      Log('Failed to install service, exit code: ' + IntToStr(ResultCode));
      MsgBox('Failed to install Windows service. You may need to run the installer as Administrator.', mbError, MB_OK);
    end;
  end;
end;

{ Pre-install checks }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';

  // Check Python
  if not CheckPython() then
  begin
    Result := 'Python 3.11 or higher is required. Please install Python and run the installer again.';
    Exit;
  end;
end;

{ Post-install tasks }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Generate configuration file
    GenerateConfigFile();

    // Install dependencies
    if MsgBox('Install Python dependencies now?' + #13#10 +
              'This will run: pip install -r requirements.txt',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      InstallDependencies();
    end;

    // Train model
    if MsgBox('Train initial ML model now?' + #13#10 +
              'This will take about 30-60 seconds.',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      TrainModel();
    end;

    // Install service
    if MsgBox('Install as Windows Service?' + #13#10 +
              'The service will start automatically on boot.',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      if InstallService() then
      begin
        // Ask to start service now
        if MsgBox('Service installed successfully. Start the service now?',
                  mbConfirmation, MB_YESNO) = IDYES then
        begin
          Exec('net', 'start {#MyAppServiceName}', '', SW_HIDE, ewNoWait, ResultCode);
        end;
      end;
    end;
  end;
end;

{ Uninstall service }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  NSSMPath: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    NSSMPath := ExpandConstant('{app}\bin\nssm.exe');

    // Stop and remove service
    Exec('net', 'stop {#MyAppServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(NSSMPath, 'remove {#MyAppServiceName} confirm', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

[Run]
; Option to open setup guide after install
Filename: "{app}\SETUP_README.md"; Description: "View Setup Guide"; Flags: postinstall shellexec skipifsilent unchecked; Components: docs
; Option to open API docs in browser
Filename: "http://localhost:8000/docs"; Description: "Open API Documentation in browser (if service is running)"; Flags: postinstall shellexec skipifsilent unchecked

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\models"
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\reports"
