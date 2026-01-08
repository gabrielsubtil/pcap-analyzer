import os
import subprocess
import sys

# Define constants
VERSION_FILE = 'version.txt'
ICON_PATH = r'src\assets\app.ico'
DIST_DIR = 'dist_windows'
EXE_NAME = 'Analisador de Pcap v5'
MAIN_SCRIPT = r'src\boot.py'

def parse_version_txt():
    """Reads key-value pairs from version.txt."""
    data = {}
    if not os.path.exists(VERSION_FILE):
        return data
    
    with open(VERSION_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('[') or ':' not in line:
                continue
            key, value = line.split(':', 1)
            data[key.strip()] = value.strip()
    return data

def generate_version_info(data):
    """Generates a text file compatible with PyInstaller --version-file."""
    
    # Defaults
    ver_str = data.get('Versão', '5.0.0.0')
    if len(ver_str.split('.')) < 4:
        ver_tuple = tuple(map(int, ver_str.split('.'))) + (0,) * (4 - len(ver_str.split('.')))
    else:
        ver_tuple = tuple(map(int, ver_str.split('.')[:4]))
    
    ver_tuple_str = str(ver_tuple)

    content = f"""
# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    # filevers and prodvers should be always a tuple with four items: (1, 2, 3, 4)
    filevers={ver_tuple_str},
    prodvers={ver_tuple_str},
    # Contains a bitmask that specifies the valid bits 'flags'r
    mask=0x3f,
    # Contains a bitmask that specifies the Boolean attributes of the file.
    flags=0x0,
    # The operating system for which this file was designed.
    # 0x4 - NT and there is no need to define different OS types.
    OS=0x40004,
    # The general type of file.
    # 0x1 - the file is an application.
    fileType=0x1,
    # The function of the file.
    # 0x0 - the function is not defined for this fileType
    subtype=0x0,
    # Creation date and time stamp.
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'041604b0',
        [StringStruct(u'CompanyName', u'{data.get("Company Name", "Gabriel Subtil")}'),
        StringStruct(u'FileDescription', u'{data.get("File Description", "PCAP Analyzer")}'),
        StringStruct(u'FileVersion', u'{ver_str}'),
        StringStruct(u'InternalName', u'{data.get("Internal Name", "pcap_analyzer")}'),
        StringStruct(u'LegalCopyright', u'{data.get("Legal Copyright", "Copyright 2026")}'),
        StringStruct(u'OriginalFilename', u'{data.get("Original Filename", EXE_NAME + ".exe")}'),
        StringStruct(u'ProductName', u'{data.get("Product Name", "Analisador de PCAP")}'),
        StringStruct(u'ProductVersion', u'{ver_str}')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1046, 1200])])
  ]
)
"""
    with open('file_version_info.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    print("file_version_info.txt generated.")

def build():
    data = parse_version_txt()
    generate_version_info(data)
    
    cmd = [
        'pyinstaller',
        '--noconfirm',
        '--onefile',
        '--windowed',
        '--clean',
        f'--icon={ICON_PATH}',
        f'--name={EXE_NAME}',
        f'--distpath={DIST_DIR}',
        '--add-data=src/frontend;frontend',
        '--add-data=src/assets;assets',
        '--version-file=file_version_info.txt',
        MAIN_SCRIPT
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    subprocess.check_call(cmd)

if __name__ == '__main__':
    build()
