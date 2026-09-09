@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "%~dp0"
cl /nologo /O2 /EHsc /W4 delivery_tests.cpp /Fe:delivery_tests.exe
if errorlevel 1 exit /b 1
delivery_tests.exe %*
exit /b %ERRORLEVEL%
