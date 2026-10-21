; SENTRIX NSIS installer hooks. Guarantees a desktop shortcut (Tauri already creates the Start Menu entry)
; and removes it on uninstall. Per-user install: no administrator rights required.

!macro NSIS_HOOK_POSTINSTALL
  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
!macroend
