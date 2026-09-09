@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /EHsc /W4 identity_tests.cpp /Fe:identity_tests.exe /link bcrypt.lib ncrypt.lib shell32.lib ole32.lib
if errorlevel 1 exit /b 1
identity_tests.exe
if errorlevel 1 exit /b 1
cl /nologo /EHsc /W4 config_tests.cpp /Fe:config_tests.exe
if errorlevel 1 exit /b 1
config_tests.exe
exit /b %ERRORLEVEL%
