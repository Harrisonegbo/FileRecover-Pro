# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Retrievo – Forensic File Recovery Tool
# Build on Windows:  pyinstaller --noconfirm retrievo.spec

import sys
from pathlib import Path

block_cipher = None
root = Path(SPECPATH)

a = Analysis(
    ['src/main.py'],
    pathex=[str(root / 'src')],
    binaries=[],
    datas=[],
    hiddenimports=[
        'customtkinter',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'core',
        'core.carver',
        'core.disk_access',
        'core.recover',
        'core.scanner',
        'core.signatures',
        'ui',
        'ui.main_window',
        'ui.results_view',
        'ui.widgets',
        'utils',
        'utils.helpers',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Collect customtkinter assets (themes, etc.)
try:
    import customtkinter
    ctk_path = Path(customtkinter.__file__).parent
    a.datas += Tree(str(ctk_path), prefix='customtkinter')
except Exception:
    pass

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Retrievo',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # GUI app – no black console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,         # Request Administrator (needed for raw disk access)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Retrievo',
)
