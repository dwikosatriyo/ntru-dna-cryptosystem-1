call ./venv/Scripts/activate

set FLASK_APP=run.py
set FLASK_ENV=development

flask run -h localhost -p 70


echo Tekan enter untuk keluar
pause>nul
cls


