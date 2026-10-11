@REM ----------------------------------------------------------------------------
@REM Licensed to the Apache Software Foundation (ASF) under one
@REM or more contributor license agreements.  See the NOTICE file
@REM distributed with this work for additional information
@REM regarding copyright ownership.  The ASF licenses this file
@REM to you under the Apache License, Version 2.0 (the
@REM "License"); you may not use this file except in compliance
@REM with the License.  You may obtain a copy of the License at
@REM
@REM    https://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing,
@REM software distributed under the License is distributed on an
@REM "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
@REM KIND, either express or implied.  See the License for the
@REM specific language governing permissions and limitations
@REM under the License.
@REM ----------------------------------------------------------------------------

@REM ----------------------------------------------------------------------------
@REM Maven Start Up Batch script
@REM
@REM Required ENV vars:
@REM JAVA_HOME - location of a JDK home dir
@REM
@REM Optional ENV vars
@REM MAVEN_BATCH_ECHO - set to 'on' to enable the echoing of the input commands
@REM MAVEN_BATCH_PAUSE - set to 'on' to pause at the end of the script
@REM MAVEN_OPTS - parameters passed to the Java VM when running Maven
@REM     e.g. to debug Maven itself, use
@REM set MAVEN_OPTS=-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000
@REM MAVEN_SKIP_RC - flag to disable loading of mavenrc files
@REM ----------------------------------------------------------------------------

@REM Begin all REM lines with '@' in case MAVEN_BATCH_ECHO is 'on'
@echo off
@setlocal EnableExtensions EnableDelayedExpansion

@REM set %ENABLE_PAUSE% to 'on' to pause at the end of this script
@set ENABLE_PAUSE=off
@if "%MAVEN_BATCH_PAUSE%"=="on" set ENABLE_PAUSE=on

@REM set %MAVEN_BATCH_ECHO% to 'on' to enable the echoing of the input commands
@if "%MAVEN_BATCH_ECHO%"=="on" echo on

@REM Execute a user defined script before this one
@if not "%MAVEN_SKIP_RC%"=="" goto skipRcPre
@if exist "%USERPROFILE%\mavenrc_pre.bat" call "%USERPROFILE%\mavenrc_pre.bat"
@if exist "%USERPROFILE%\mavenrc_pre.cmd" call "%USERPROFILE%\mavenrc_pre.cmd"
:skipRcPre

@set ERROR_CODE=0

@REM To isolate internal variables from possible post scripts, we use another setlocal
@setlocal

@REM ==== START VALIDATION ====
@REM Check if java.exe is available
if not "%JAVA_HOME%"=="" (
    if exist "%JAVA_HOME%\bin\java.exe" goto okJava
)
where java >nul 2>&1
if "%ERRORLEVEL%"=="0" goto okJava

echo.
echo Error: JAVA_HOME is not defined correctly.
echo We cannot execute java.exe
echo.
set ERROR_CODE=1
goto end

:okJava
@REM Re-use local maven if present in C:\tools
if exist "C:\tools\apache-maven-3.9.9\bin\mvn.cmd" (
    call "C:\tools\apache-maven-3.9.9\bin\mvn.cmd" %*
    set ERROR_CODE=%ERRORLEVEL%
    goto end
)

@REM Re-use local workspace maven if present in temp/
if exist "%~dp0temp\maven\apache-maven-3.9.9\bin\mvn.cmd" (
    call "%~dp0temp\maven\apache-maven-3.9.9\bin\mvn.cmd" %*
    set ERROR_CODE=%ERRORLEVEL%
    goto end
)

@REM Fallback to PATH mvn
where mvn >nul 2>&1
if "%ERRORLEVEL%"=="0" (
    call mvn %*
    set ERROR_CODE=%ERRORLEVEL%
    goto end
)

@REM Download and execute wrapper
set WRAPPER_DIR=%~dp0.mvn\wrapper
set WRAPPER_JAR=%WRAPPER_DIR%\maven-wrapper.jar
if exist "%WRAPPER_JAR%" goto runWrapper

if not exist "%WRAPPER_DIR%" mkdir "%WRAPPER_DIR%"
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.2/maven-wrapper-3.3.2.jar', '%WRAPPER_JAR%')"

:runWrapper
if not "%JAVA_HOME%"=="" (
    set "JAVACMD=%JAVA_HOME%\bin\java.exe"
) else (
    set "JAVACMD=java"
)

"%JAVACMD%" %MAVEN_OPTS% -jar "%WRAPPER_JAR%" %*
set ERROR_CODE=%ERRORLEVEL%

:end
@endlocal & set ERROR_CODE=%ERROR_CODE%

if "%MAVEN_BATCH_PAUSE%"=="on" pause

if not "%MAVEN_SKIP_RC%"=="" goto skipRcPost
@if exist "%USERPROFILE%\mavenrc_post.bat" call "%USERPROFILE%\mavenrc_post.bat"
@if exist "%USERPROFILE%\mavenrc_post.cmd" call "%USERPROFILE%\mavenrc_post.cmd"
:skipRcPost

if %ERROR_CODE% neq 0 exit /b %ERROR_CODE%
