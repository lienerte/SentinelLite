@echo off
title SentinelLite Security Core Launch Engine
echo ============================================================
echo 🚨 STARTING SENTINELLITE LOCAL ANALYTICAL CORE
echo ============================================================
echo Please leave this window open while using the dashboard.
echo.

:: 1. Start the backend executable in a parallel background window
echo [*] Initializing rules framework and parsing signature indices...
start "" SentinelLite.exe

:: 2. Pause for 5 seconds to let the 3,100+ signatures compile into memory
timeout /t 5 /nobreak > pps

:: 3. Now snap the web dashboard open once the server port is active
echo [+] Opening web management console...
start http://127.0.0.1:5000

exit