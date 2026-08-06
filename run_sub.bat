@echo off
title Standalone Node.js Subscription Server
echo Checking for Node.js...
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js is not installed or not in your PATH.
    echo Please install Node.js from https://nodejs.org/ before running this script.
    pause
    exit /b
)
echo Starting subscription server...
node simple_sub.js
pause
