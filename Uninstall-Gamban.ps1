# Uninstall-Gamban.ps1
# Script to completely remove Gamban from the system including DNS restrictions
# Created: 2025-04-11
# Last modified: 2025-04-11
# 
# Run as Administrator: Right-click and select "Run with PowerShell"

# Function to write colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput Green "Starting Gamban uninstallation process..."

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-ColorOutput Red "This script requires administrator privileges. Please run as administrator."
    exit 1
}

# Step 1: Stop the Gamban service if it's running
Write-ColorOutput Yellow "Stopping Gamban service..."
$service = Get-Service -Name "Gamban" -ErrorAction SilentlyContinue
if ($service) {
    try {
        Stop-Service -Name "Gamban" -Force -ErrorAction Stop
        Write-ColorOutput Green "Gamban service stopped successfully."
    }
    catch {
        Write-ColorOutput Red "Failed to stop Gamban service: $_"
    }
}
else {
    Write-ColorOutput Yellow "Gamban service not found."
}

# Step 2: Kill any running Gamban processes
Write-ColorOutput Yellow "Terminating any running Gamban processes..."
Get-Process | Where-Object {$_.ProcessName -like "*Gamban*"} | ForEach-Object {
    try {
        $_ | Stop-Process -Force -ErrorAction Stop
        Write-ColorOutput Green "Process $($_.ProcessName) terminated."
    }
    catch {
        Write-ColorOutput Red "Failed to terminate process $($_.ProcessName): $_"
    }
}

# Step 3: Uninstall the Gamban service
Write-ColorOutput Yellow "Uninstalling Gamban service..."
try {
    $servicePath = (Get-WmiObject Win32_Service -Filter "Name='Gamban'").PathName
    if ($servicePath) {
        $servicePath = $servicePath.Trim('"')
        Write-ColorOutput Yellow "Service executable path: $servicePath"
        
        # Use sc.exe to delete the service
        $result = sc.exe delete Gamban
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput Green "Gamban service uninstalled successfully."
        }
        else {
            Write-ColorOutput Red "Failed to uninstall Gamban service. Exit code: $LASTEXITCODE"
        }
    }
    else {
        Write-ColorOutput Yellow "Could not determine Gamban service path."
    }
}
catch {
    Write-ColorOutput Red "Error uninstalling Gamban service: $_"
}

# Step 4: Remove Gamban application files
Write-ColorOutput Yellow "Removing Gamban application files..."

# Main application directory
$appPath = "$env:LOCALAPPDATA\BeanstalkHPS"
if (Test-Path $appPath) {
    try {
        Remove-Item -Path $appPath -Recurse -Force -ErrorAction Stop
        Write-ColorOutput Green "Removed Gamban application files from $appPath"
    }
    catch {
        Write-ColorOutput Red "Failed to remove Gamban application files: $_"
    }
}
else {
    Write-ColorOutput Yellow "Gamban application directory not found at $appPath"
}

# Step 5: Clean up registry entries
Write-ColorOutput Yellow "Cleaning up registry entries..."

# Check both 64-bit and 32-bit uninstall registry locations
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$gambanFound = $false
foreach ($path in $registryPaths) {
    $gambanEntries = Get-ItemProperty $path | Where-Object { $_.DisplayName -like "*Gamban*" }
    foreach ($entry in $gambanEntries) {
        $gambanFound = $true
        try {
            $registryPath = $entry.PSPath
            Remove-Item -Path $registryPath -Force -ErrorAction Stop
            Write-ColorOutput Green "Removed registry entry: $registryPath"
        }
        catch {
            Write-ColorOutput Red "Failed to remove registry entry: $_"
        }
    }
}

if (-not $gambanFound) {
    Write-ColorOutput Yellow "No Gamban registry entries found."
}

# Check for Gamban in the current user's Run registry
$runPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$runEntries = Get-ItemProperty -Path $runPath -ErrorAction SilentlyContinue
if ($runEntries) {
    $gambanRunEntries = $runEntries.PSObject.Properties | Where-Object { $_.Name -like "*Gamban*" -or $_.Value -like "*Gamban*" }
    foreach ($entry in $gambanRunEntries) {
        try {
            Remove-ItemProperty -Path $runPath -Name $entry.Name -Force -ErrorAction Stop
            Write-ColorOutput Green "Removed autostart entry: $($entry.Name)"
        }
        catch {
            Write-ColorOutput Red "Failed to remove autostart entry: $_"
        }
    }
}