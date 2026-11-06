@echo off
title Orion Threat Intelligence - CLI Shell
echo [*] Launching Orion CTI Terminal...
cd /d "%~dp0"
mvn org.codehaus.mojo:exec-maven-plugin:3.1.0:java -Dexec.mainClass="ca.yorku.eecs3311.orion.boundary.OrionCLI"
pause