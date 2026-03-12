@echo off
:: IP Enrichment — Service startup script
:: Used by NSSM to launch the web server as a Windows service.

:: Move to the project directory (same folder as this script)
cd /d "%~dp0"

:: Launch the web app using the virtualenv Python
venv\Scripts\python.exe web\app.py
