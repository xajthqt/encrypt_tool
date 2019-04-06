set LAST_CD=%cd%
echo 当前盘符和路径：%~dp0
set bashpath=%~dp0
echo %bashpath%
cd /d %bashpath%

rd /S /Q build
rd /S /Q dist
python mysetup.py py2exe
xcopy bitbug_favicon.ico .\dist\ /y
xcopy *.pem .\dist\ /y
xcopy info.conf .\dist\ /y
cd /d %LAST_CD%
