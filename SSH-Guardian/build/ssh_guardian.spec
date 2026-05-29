# -*- mode: python ; coding: utf-8 -*-
"""
SSH Guardian — PyInstaller spec file
------------------------------------
Tek dosya (one-file) executable üretir. matplotlib, PyQt5, maxminddb gibi
runtime bağımlılıkları otomatik toplanır.

Kullanım:
    cd SSH-Guardian
    pip install pyinstaller
    pyinstaller build/ssh_guardian.spec --clean

Çıktı:
    Linux/macOS  ->  dist/SSH-Guardian
    Windows      ->  dist/SSH-Guardian.exe

NOT: 'console=False' GUI uygulaması olduğu için terminal penceresi açılmaz.
"""

import os

# spec çalıştırıldığı klasör genelde 'build/' olur — projeyi root'a relatif çöz.
project_root = os.path.abspath(os.path.join(os.getcwd()))

block_cipher = None


# ----------------------------------------------------------------------
# Analysis: kaynak kodu tara, importları bul
# ----------------------------------------------------------------------
a = Analysis(
    ['main.py'],
    pathex=[project_root],
    binaries=[],
    datas=[
        # Örnek log ve (varsa) GeoIP veritabanını binary'ye paketleyelim:
        ('logs/sample_auth.log', 'logs'),
        # assets klasöründeki tüm dosyaları (ikonlar, mmdb, vb.) ekle:
        # ('assets', 'assets'),  # mmdb eklemek isterseniz yorumdan çıkarın
    ],
    hiddenimports=[
        # matplotlib backend'i bazen otomatik tespit edilemez:
        'matplotlib.backends.backend_qt5agg',
        # maxminddb opsiyonel; kuruluysa dahil et:
        'maxminddb',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Büyük ve gereksiz modüller — boyutu küçültür:
        'tkinter', 'unittest', 'pytest', 'IPython', 'jupyter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ----------------------------------------------------------------------
# EXE: tek dosya (onefile)
# ----------------------------------------------------------------------
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SSH-Guardian',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                # ikili boyutunu küçültür (upx yüklü olmalı)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # GUI app -> terminal açma
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/icon.ico',   # opsiyonel — kendi ikonunuzu koyabilirsiniz
)
