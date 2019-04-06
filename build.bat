set LAST_CD=%cd%
cd %~dp0
python mysetup.py py2exe
xcopy bitbug_favicon.ico .\dist\ /y
xcopy *.pem .\dist\ /y
xcopy info.conf .\dist\ /y
cd %LAST_CD%
