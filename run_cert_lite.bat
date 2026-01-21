@echo off
echo Checking dependencies...
pip install ttkbootstrap >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing ttkbootstrap...
    pip install ttkbootstrap
)

echo Starting CertLite...
start /b pythonw cert_lite.py
exit
