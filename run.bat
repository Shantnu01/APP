@echo off
title RepoGuard - Vulnerability Auditor
echo =======================================================
echo   Launching RepoGuard Security & Dependency Auditor
echo   Team: Shantnu, Arya Agrawal, Raiyan Kamal
echo   Course: Advanced Programming Practices (Section H2)
echo =======================================================
echo.

python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Application failed to start.
    echo Please ensure Python 3.9+ with Tkinter is installed.
    pause
)
