@echo off
cls
setlocal enabledelayedexpansion

title Running %~n0

:start
echo Start %~n0
title Running %~n0

::-----------------------------------------------------------------------------------------------
:: to test the making of an inventory
::-----------------------------------------------------------------------------------------------
set NET=192.168.1
python.exe %~n0.py -N "%NET%"
python.exe %~n0.py -N "%NET%" -P "%~n0_%NET%.lst"
echo.
::-----------------------------------------------------------------------------------------------

:end
echo End   %~n0
title ""
::pause