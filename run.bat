@echo off

REM Run go mod tidy to ensure dependencies are installed
go mod tidy
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [91mError executing go mod tidy. Please check your dependencies.[0m
    exit /b %ERRORLEVEL%
)

REM Run the tests
go test -v
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [91mTests failed. Build aborted.[0m
    exit /b %ERRORLEVEL%
)

REM Set the environment variable to disable CGO
set CGO_ENABLED=0

REM Build the Go project to create lockit.exe
go build -trimpath -ldflags "-s -w" -o lockit.exe main.go
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [91mBuild failed. Please check your code.[0m
    exit /b %ERRORLEVEL%
)

REM Create the C:\LockIt directory if it doesn't exist
echo Creating directory C:\LockIt
mkdir "C:\LockIt" 2>nul

REM Move lockit.exe to the C:\LockIt directory
echo Moving lockit.exe to C:\LockIt
copy lockit.exe "C:\LockIt\lockit.exe"

REM Add C:\LockIt to PATH without truncating
for /f "tokens=2 delims==" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path ^| findstr Path') do set OLD_PATH=%%A
echo Adding C:\LockIt to system PATH
setx PATH "%OLD_PATH%;C:\LockIt"

REM Delete temporary files
del test_invalid_key.txt

echo.
echo [92mBuild successful! lockit.exe has been moved to C:\LockIt and is now available in your PATH. You can run it directly from CMD or PowerShell.[0m
pause
