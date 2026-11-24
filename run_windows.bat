@echo off
cd /d "%~dp0"
if not exist venv python -m venv venv
call venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Optional but recommended: train the URL ML model now.
echo Run: python train_model.py
echo.
python app.py
pause
