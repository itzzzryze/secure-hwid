@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /W4 hardware_probe.cpp /Fe:hardware_probe.exe /link shell32.lib ole32.lib
if errorlevel 1 exit /b 1
hardware_probe.exe
exit /b %ERRORLEVEL%
