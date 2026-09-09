@echo off
REM Build script: needs VS x64 env
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /W3 /GS /sdl /guard:cf /DUNICODE /D_UNICODE main.cpp /Fe:HWID.exe ^
   /link /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" /MANIFESTINPUT:app.manifest ^
   kernel32.lib user32.lib gdi32.lib advapi32.lib dwmapi.lib gdiplus.lib bcrypt.lib ntdll.lib shell32.lib winmm.lib ole32.lib
echo Build exit: %ERRORLEVEL%
if errorlevel 1 exit /b 1
cl /nologo /O2 /EHsc /W3 /GS /sdl /guard:cf /DUNICODE /D_UNICODE decrypt.cpp /Fe:HWID-decrypt.exe /link /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /guard:cf /SUBSYSTEM:CONSOLE
exit /b %ERRORLEVEL%
