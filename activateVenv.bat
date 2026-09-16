echo off

set PYTHONPATH=%~dp0
echo Adding %PYTHONPATH% to PYTHONPATH.

echo Activating Venv.
cmd /k %~dp0.venv\Scripts\activate.bat
