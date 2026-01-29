# Certificate Manager GUI

A companion tool to `signertoolgui` for browsing and managing Windows certificates.

## Features

- **Browse stores**:
  - `CurrentUser\My` (Personal)
  - `CurrentUser\Root` (Trusted Root)
  - `CurrentUser\TrustedPublisher`
  - `LocalMachine\My` (Personal)
  - `LocalMachine\Root` (Trusted Root)
  - `LocalMachine\TrustedPublisher`
- **View details**:
  - Subject
  - SHA1 thumbprint
  - Expiration (`NotAfter`)
- **PFX import**:
  - Import a `.pfx` file into the currently selected store using `certutil`

## Requirements

- Windows 10/11
- Python 3.6+ (tkinter included)
- `certutil.exe` (part of Windows)

## Running

From this folder:

```bash
python certmanagergui.py
```

Or on Windows, double-click `run_certmanager.bat`.

## Notes

- Importing into `LocalMachine\*` stores may require administrator privileges.
- PFX import uses `certutil -f -p <password> -importpfx <store> <file.pfx>`.

