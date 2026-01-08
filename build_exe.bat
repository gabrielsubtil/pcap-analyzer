@echo off
echo Compilando PCAP Analyzer...
echo Certifique-se de ter instalado: pip install pyinstaller pywebview

if not exist "dist" mkdir dist



py -3.12 -m PyInstaller --noconsole --onefile ^
    --name "PCAP Analyzer" ^
    --add-data "src/frontend;frontend" ^
    --icon=NONE ^
    src/boot.py

echo.
echo Build concluido! O executavel esta na pasta 'dist'.
pause
