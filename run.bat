@echo off
chcp 65001 >nul
echo ============================================
echo         تشغيل برنامج Al-Masrya
echo ============================================
if not exist venv (
    echo إنشاء بيئة بايثون...
    python -m venv venv
)
call venv\Scripts\activate
echo تثبيت المتطلبات...
pip install -r requirements.txt --quiet
echo تشغيل البرنامج...
echo افتح المتصفح على: http://127.0.0.1:5000
start http://127.0.0.1:5000
python app.py
pause
