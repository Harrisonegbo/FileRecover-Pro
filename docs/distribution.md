# Distributing Retrievo for Windows

## Portable executable (recommended)

1. On a Windows machine run `build.bat`.
2. Zip the folder `dist\Retrievo\`.
3. Users unzip and run `Retrievo.exe` (no install needed).

The app requests Administrator elevation automatically (`uac_admin=True` in the spec) so raw disk access works when the user approves the UAC prompt.

## GitHub Releases

Tag a version and push:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds the zip and attaches it to the release page.

## Optional: full installer (Inno Setup)

If you want a classic Setup.exe:

1. Install [Inno Setup](https://jrsoftware.org/isinfo.php).
2. Point it at `dist\Retrievo\Retrievo.exe` and the accompanying DLLs/folders.
3. Compile → produce `Retrievo-Setup-x64.exe`.

A minimal Inno script example:

```iss
[Setup]
AppName=Retrievo
AppVersion=1.0
DefaultDirName={autopf}\Retrievo
OutputBaseFilename=Retrievo-Setup-x64
PrivilegesRequired=admin

[Files]
Source: "dist\Retrievo\*"; DestDir: "{app}"; Flags: recursesubdirs

[Icons]
Name: "{group}\Retrievo"; Filename: "{app}\Retrievo.exe"
Name: "{commondesktop}\Retrievo"; Filename: "{app}\Retrievo.exe"
```

## Note about APK

APK files are for **Android only**. Retrievo is a **Windows desktop** forensic tool and is distributed as `.exe` / zip, not APK.
