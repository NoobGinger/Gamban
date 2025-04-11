# Gamban Uninstaller
**Created: 2025-04-11**
**Last modified: 2025-04-11**

A specialized PowerShell script to fully remove Gamban from your PC, including hidden DNS settings in browsers and registry policies.

## Quick Start

1. **Right-click** on `Uninstall-Gamban.ps1`
2. Select **"Run with PowerShell"**
3. Wait for the script to complete
4. **Restart your computer**

## What This Script Removes

- Gamban services and processes
- Application files and registry entries
- Browser DNS settings (Chrome, Firefox, Edge)
- System-wide DNS policies
- DNS settings on all network interfaces

## Troubleshooting

If you're still having issues accessing previously blocked sites:

1. Make sure you **restart your computer** after running the script
2. Try clearing your browser cache
3. For Chrome users, type `chrome://net-internals/#dns` in the address bar and click "Clear host cache"
4. For Firefox users, go to Settings → Network Settings and ensure "Enable DNS over HTTPS" is disabled

## Advanced Usage

If running as administrator directly:

```powershell
powershell -ExecutionPolicy Bypass -File Uninstall-Gamban.ps1
```

## System Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or higher
- Administrator privileges