; Extra files of MCP Keyholder next to the app: kh.exe (MCP shim for agents) and
; keyholder-service.exe (service mode). Both are built by scripts/release.ps1 before bundling.
; Tauri copies this file to target/release/nsis/x64 before running makensis, so paths are
; relative to that folder: ..\..\ is target/release.

!macro NSIS_HOOK_PREINSTALL
  ; kh.exe may be running (an agent keeps its MCP server open). A running exe cannot be
  ; overwritten but can be renamed; the old copy is removed on the next reboot.
  Delete "$INSTDIR\kh.exe.old"
  Delete "$INSTDIR\keyholder-service.exe.old"
  Rename "$INSTDIR\kh.exe" "$INSTDIR\kh.exe.old"
  Rename "$INSTDIR\keyholder-service.exe" "$INSTDIR\keyholder-service.exe.old"
  Delete /REBOOTOK "$INSTDIR\kh.exe.old"
  Delete /REBOOTOK "$INSTDIR\keyholder-service.exe.old"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  SetOutPath "$INSTDIR"
  File "${__FILEDIR__}\..\..\kh.exe"
  File "${__FILEDIR__}\..\..\keyholder-service.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$INSTDIR\kh.exe"
  Delete "$INSTDIR\kh.exe.old"
  Delete "$INSTDIR\keyholder-service.exe"
  Delete "$INSTDIR\keyholder-service.exe.old"
!macroend
