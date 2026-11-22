#ifndef SourceRoot
  #define SourceRoot ".."
#endif
#ifndef PayloadDir
  #define PayloadDir "..\artifacts\SentinelCoreSetup\payload"
#endif
#ifndef ModelsDir
  #define ModelsDir "..\artifacts\SentinelCoreSetup\models"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{9D23B174-C7DA-4AAC-8CC1-0EED1E7404D5}
AppName=SentinelCore
AppVersion=1.0.0
AppPublisher=SentinelCore — projet académique
DefaultDirName={localappdata}\Programs\SentinelCore
DefaultGroupName=SentinelCore
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputDir="{#OutputDir}"
OutputBaseFilename=SentinelCore-Setup-1.0.0
SetupIconFile="{#SourceRoot}\Control Center\Assets\SentinelCore.ico"
UninstallDisplayIcon={app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
DisableWelcomePage=no
UsePreviousAppDir=yes
Uninstallable=yes
VersionInfoVersion=1.0.0.0
VersionInfoCompany=SentinelCore
VersionInfoDescription=Installateur SentinelCore
VersionInfoProductName=SentinelCore

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Créer un raccourci sur le Bureau"; GroupDescription: "Raccourcis :"; Flags: unchecked

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ModelsDir}\*"; DestDir: "{localappdata}\SentinelCore\Demon1Learning\models"; Flags: ignoreversion uninsneveruninstall

[Icons]
Name: "{autoprograms}\SentinelCore"; Filename: "{app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe"; WorkingDir: "{app}"; IconFilename: "{app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe"
Name: "{autodesktop}\SentinelCore"; Filename: "{app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe"; WorkingDir: "{app}"; IconFilename: "{app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe"; Description: "Lancer SentinelCore"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'SentinelCoreControlCenter');
end;
