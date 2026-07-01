#define MyAppName "FluxForm"
#define MyAppVersion "0.1.1"
#define MyAppPublisher "FluxForm"
#define MyAppExeName "FluxForm.WPF.exe"

[Setup]
AppId={{44C1E0DD-7D71-4F9E-8F58-54F6D7B98011}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\FluxForm
DefaultGroupName={#MyAppName}
DisableDirPage=no
DisableProgramGroupPage=yes
OutputDir=..\publish\installer
OutputBaseFilename=FluxFormSetup-0.1.1
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimp"; MessagesFile: ".\Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\publish\wpf\FluxForm.WPF.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\publish\wpf\FluxForm.Core.pdb"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\publish\wpf\FluxForm.WPF.pdb"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\publish\wpf\tools\ffmpeg\*"; DestDir: "{app}\tools\ffmpeg"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\FluxForm"; Filename: "{app}\FluxForm.WPF.exe"
Name: "{userdesktop}\FluxForm"; Filename: "{app}\FluxForm.WPF.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,FluxForm}"; Flags: nowait postinstall skipifsilent
