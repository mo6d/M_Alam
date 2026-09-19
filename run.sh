#!/usr/bin/env bash
set -e
echo "============================================"
echo "         تشغيل برنامج Al-Masrya"
echo "============================================"
if [ ! -d "venv" ]; then
    echo "إنشاء بيئة بايثون..."
    python3 -m venv venv
fi
source venv/bin/activate
echo "تثبيت المتطلبات..."
pip install -r requirements.txt --quiet
echo "تشغيل البرنامج..."
echo "افتح المتصفح على: http://127.0.0.1:5000"
python3 app.py
