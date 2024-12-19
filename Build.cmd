@echo off
chcp 65001

dotnet restore
msbuild /p:Configuration=Release /p:Platform=x64 /m
msbuild /p:Configuration=Debug /p:Platform=x64 /m
copy Terminal\Windows\win-aisio.ps1 bin\x64\Debug\win-aisio.ps1
copy Terminal\Windows\Aisio-powershell-function.ps1 bin\x64\Debug\Aisio-powershell-function.ps1
copy Terminal\Windows\win-aisio.ps1 bin\x64\Release\win-aisio.ps1
copy Terminal\Windows\Aisio-powershell-function.ps1 bin\x64\Release\Aisio-powershell-function.ps1

pause
echo on