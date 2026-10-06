; Hydra Multipath Proxy — Windows installer (NSIS 3)
; Built by CI:  makensis /DAPPVERSION=v0.2.0 packaging\hydra.nsi   (run from repo root)
; Installs: GUI + CLI + official signed wintun.dll, Start Menu & Desktop shortcuts,
;           uninstaller + Add/Remove Programs entry.
; GUI shortcut requests admin elevation (UAC) on launch — required for TUN mode.

Unicode true
ManifestDPIAware true

!define APPNAME "Hydra Multipath Proxy"
!define COMPANY "fuzhusi"
!define GUIEXE "hydra-client-gui.exe"
!define CLIEXE "hydra-client.exe"

!ifndef APPVERSION
  !define APPVERSION "dev"
!endif

Name "${APPNAME} ${APPVERSION}"
OutFile "dist\Hydra-Setup-${APPVERSION}-x64.exe"
InstallDir "$PROGRAMFILES64\Hydra"
InstallDirRegKey HKLM "Software\Hydra" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
; Installer icon (repo file; also embeds into uninstaller)
Icon "hydra-client-gui\assets\app.ico"
UninstallIcon "hydra-client-gui\assets\app.ico"

Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "..\dist\${GUIEXE}"
  File "..\dist\${CLIEXE}"
  File "..\dist\wintun.dll"
  File "..\dist\README.md"

  ; GUI runtime needs admin for TUN mode — mark shortcut to request UAC elevation
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" \
    "$INSTDIR\${GUIEXE}" "~ RUNASADMIN"

  CreateDirectory "$SMPROGRAMS\Hydra"
  CreateShortCut "$SMPROGRAMS\Hydra\Hydra Proxy.lnk" "$INSTDIR\${GUIEXE}" "" "$INSTDIR\${GUIEXE}" 0
  CreateShortCut "$DESKTOP\Hydra Proxy.lnk" "$INSTDIR\${GUIEXE}" "" "$INSTDIR\${GUIEXE}" 0

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra" \
    "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra" \
    "DisplayVersion" "${APPVERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra" \
    "Publisher" "${COMPANY}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra" \
    "DisplayIcon" "$INSTDIR\${GUIEXE}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra" \
    "UninstallString" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  ; stop a running GUI so files are not locked (best-effort)
  nsExec::ExecToLog 'taskkill /IM ${GUIEXE} /F'
  Delete "$INSTDIR\${GUIEXE}"
  Delete "$INSTDIR\${CLIEXE}"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Hydra\Hydra Proxy.lnk"
  RMDir "$SMPROGRAMS\Hydra"
  Delete "$DESKTOP\Hydra Proxy.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Hydra"
  DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" \
    "$INSTDIR\${GUIEXE}"
  DeleteRegKey /ifempty HKLM "Software\Hydra"
  ; user config (%APPDATA%\hydra) is intentionally kept — reinstall restores it
SectionEnd
