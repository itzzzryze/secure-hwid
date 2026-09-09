@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /W3 /DUNICODE /D_UNICODE render_preview.cpp /Fe:render_preview.exe /link /SUBSYSTEM:CONSOLE ole32.lib
if errorlevel 1 exit /b 1
render_preview.exe
exit /b %ERRORLEVEL%
