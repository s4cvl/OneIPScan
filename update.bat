@echo off
:: IP Enrichment — Update script
:: Pulls latest code from GitHub and restarts the Windows service.
:: Run as Administrator.

cd /d "%~dp0"
echo [1/3] Pulling latest code from GitHub...
git pull origin main
if %errorlevel% neq 0 (
    echo ERROR: git pull failed. Aborting.
    pause
    exit /b 1
)

echo [2/3] Installing any new dependencies...
venv\Scripts\python.exe -m pip install -r requirements.txt -q

echo [3/3] Restarting service...
nssm restart IPEnrichment

echo.
echo Done. Service restarted with latest code.
pause
