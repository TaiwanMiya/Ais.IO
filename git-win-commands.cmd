@echo off
chcp 65001
set mainPath=%~dp0%

:menu
cls
echo ^|===================================^|
echo ^|        Git Operations Menu        ^|
echo ^|===================================^|
echo ^|0. Git Exit                        ^|
echo ^|1. Git Clone                       ^|
echo ^|2. Git Diff                        ^|
echo ^|3. Git Log                         ^|
echo ^|4. Git Fetch and Parse Version     ^|
echo ^|5. Git Pull                        ^|
echo ^|6. Git Push                        ^|
echo ^|===================================^|
set /p choice="Please select the action you want to perform (0-6):"

if "%choice%"=="0" goto git_exit
if "%choice%"=="1" goto git_clone
if "%choice%"=="2" goto git_diff
if "%choice%"=="3" goto git_log
if "%choice%"=="4" goto git_parse
if "%choice%"=="5" goto git_pull
if "%choice%"=="6" goto git_push

echo Invalid selection, please select again.
pause
goto menu

:git_clone
echo You chose - Git Clone
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks clone https://github.com/TaiwanMiya/Ais.IO.git Ais.IO
pause
goto menu

:git_diff
echo You chose - Git Diff
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks --no-pager diff
pause
goto menu

:git_log
echo You chose - Git Log
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks --no-pager log --decorate --graph --all
pause
goto menu

:git_parse
echo You chose - Git Fetch and Parse Version
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks fetch -v --tags origin
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks rev-parse HEAD
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks rev-parse @{u}
pause
goto menu

:git_pull
echo You chose - Git Pull
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks reset --hard origin/master
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks clean -fd
git pull
pause
goto menu

:git_push
echo You chose - Git Push
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks add -f -- .
set /p commit_message="Please enter commit message:"
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks commit -v -q -m "%commit_message%"
git -c diff.mnemonicprefix=false -c core.quotepath=false --no-optional-locks push -v --tags origin master:master
pause
goto menu

:git_exit
cd %mainPath%
echo on
