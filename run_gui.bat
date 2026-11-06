@echo off
title Orion Threat Intelligence - GUI
echo [*] Cleaning and compiling latest code changes...
cd /d "%~dp0"
mvn clean compile javafx:run
pause