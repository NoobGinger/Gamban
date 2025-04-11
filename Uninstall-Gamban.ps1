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

# Step 6: Remove Start Menu shortcuts
Write-ColorOutput Yellow "Removing Start Menu shortcuts..."
$startMenuPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
)

foreach ($startMenuPath in $startMenuPaths) {
    $gambanShortcuts = Get-ChildItem -Path $startMenuPath -Recurse -Filter "*Gamban*.lnk" -ErrorAction SilentlyContinue
    foreach ($shortcut in $gambanShortcuts) {
        try {
            Remove-Item -Path $shortcut.FullName -Force -ErrorAction Stop
            Write-ColorOutput Green "Removed shortcut: $($shortcut.FullName)"
        }
        catch {
            Write-ColorOutput Red "Failed to remove shortcut: $_"
        }
    }
}

# Final check to see if any Gamban processes are still running
$remainingProcesses = Get-Process | Where-Object {$_.ProcessName -like "*Gamban*"}
if ($remainingProcesses) {
    Write-ColorOutput Yellow "Warning: The following Gamban processes are still running:"
    $remainingProcesses | ForEach-Object {
        Write-ColorOutput Yellow "- $($_.ProcessName) (PID: $($_.Id))"
    }
    Write-ColorOutput Yellow "You may need to restart your computer to complete the uninstallation."
}
else {
    Write-ColorOutput Green "No Gamban processes detected."
}

# Step 7: Clean up DNS and network settings
Write-ColorOutput Yellow "Cleaning up DNS and network settings..."

# Reset DNS settings to default on ALL interfaces, including virtual ones
try {
    # Check for and reset DNS on active adapters
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($adapter in $networkAdapters) {
        Write-ColorOutput Yellow "Resetting DNS settings for adapter: $($adapter.Name)"
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
        Write-ColorOutput Green "DNS settings reset to default for adapter: $($adapter.Name)"
    }
    
    # Check for and reset DNS on ALL interfaces, including virtual and loopback interfaces
    $allInterfaces = Get-DnsClientServerAddress -AddressFamily IPv4
    
    # Look specifically for Gamban DNS entries
    $gambanDnsServers = @("139.59.163.174", "18.192.31.75")
    $gambanRelatedInterfaces = $allInterfaces | Where-Object { 
        $interface = $_
        $hasGambanDns = $false
        foreach ($ip in $gambanDnsServers) {
            if ($interface.ServerAddresses -contains $ip) {
                $hasGambanDns = $true
                break
            }
        }
        $hasGambanDns
    }
    
    # Reset any interface with Gamban DNS
    foreach ($interface in $gambanRelatedInterfaces) {
        Write-ColorOutput Yellow "Found Gamban DNS settings on interface: $($interface.InterfaceAlias)"
        Write-ColorOutput Yellow "DNS servers: $($interface.ServerAddresses -join ', ')"
        Set-DnsClientServerAddress -InterfaceAlias $interface.InterfaceAlias -ResetServerAddresses -ErrorAction Stop
        Write-ColorOutput Green "Reset DNS settings on interface: $($interface.InterfaceAlias)"
    }
    
    # Also specifically check and reset common virtual interfaces
    $virtualInterfaces = @("Loopback Pseudo-Interface 1", "vEthernet (Default Switch)")
    foreach ($vInterface in $virtualInterfaces) {
        try {
            $dnsSettings = Get-DnsClientServerAddress -InterfaceAlias $vInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dnsSettings -and $dnsSettings.ServerAddresses.Count -gt 0) {
                Write-ColorOutput Yellow "Resetting DNS settings for virtual interface: $vInterface"
                Set-DnsClientServerAddress -InterfaceAlias $vInterface -ResetServerAddresses -ErrorAction Stop
                Write-ColorOutput Green "Reset DNS settings on virtual interface: $vInterface"
            }
        } catch {
            Write-ColorOutput Yellow "Could not check or reset virtual interface $vInterface : $_"
        }
    }
}
catch {
    Write-ColorOutput Red "Failed to reset DNS settings: $_"
}

# Flush DNS cache
try {
    Write-ColorOutput Yellow "Flushing DNS cache..."
    Clear-DnsClientCache -ErrorAction Stop
    Write-ColorOutput Green "DNS cache flushed successfully."
}
catch {
    Write-ColorOutput Red "Failed to flush DNS cache: $_"
}

# Check DNS client service status without trying to restart it
try {
    Write-ColorOutput Yellow "Checking DNS client service status..."
    $dnsService = Get-Service -Name "Dnscache" -ErrorAction Stop
    Write-ColorOutput Green "DNS client service is $($dnsService.Status)."
    Write-ColorOutput Yellow "Note: DNS client service is essential and will not be restarted automatically."
    Write-ColorOutput Yellow "DNS settings have been reset and cache has been flushed."
}
catch {
    Write-ColorOutput Red "Failed to check DNS client service status: $_"
}

# Step 8: Reset browser DNS settings
Write-ColorOutput Yellow "Resetting browser DNS settings..."

# Chrome DNS settings
try {
    Write-ColorOutput Yellow "Checking for Chrome DNS settings..."
    
    # Get all Chrome profiles
    $chromeUserDataDir = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    $chromeProfiles = @("Default")
    
    if (Test-Path $chromeUserDataDir) {
        # Add all numbered profiles
        $chromeProfiles += Get-ChildItem -Path $chromeUserDataDir -Directory | Where-Object { $_.Name -match "Profile \d+" } | ForEach-Object { $_.Name }
    }
    
    Write-ColorOutput Yellow "Found Chrome profiles: $($chromeProfiles -join ', ')"
    
    # Process all profiles
    foreach ($profile in $chromeProfiles) {
        $profilePath = Join-Path $chromeUserDataDir $profile
        
        # Files to check in each profile
        $filesToCheck = @(
            "Preferences",
            "Secure Preferences",
            "Local State"
        )
        
        foreach ($file in $filesToCheck) {
            $path = Join-Path $profilePath $file
            if (Test-Path $path) {
                Write-ColorOutput Yellow "Found Chrome settings at: $path"
                try {
                    # Backup the file first
                    Copy-Item -Path $path -Destination "$path.backup" -Force -ErrorAction Stop
                    Write-ColorOutput Green "Created backup at: $path.backup"
                    
                    # Read the file content
                    $content = Get-Content -Path $path -Raw -ErrorAction Stop
                    $originalContent = $content
                    $modified = $false
                    
                    # Check and remove all DNS-related settings 
                    if ($content -match '"dns_over_https"' -or 
                        $content -match '"use_dns_https_sockets"' -or 
                        $content -match '"dns_over_https_servers"' -or
                        $content -match '"secure_dns"' -or
                        $content -match '"discovery_method"' -or
                        $content -match '"doh_templates"' -or
                        $content -match '"dns"' -or
                        $content -match 'gamban') {
                        
                        Write-ColorOutput Yellow "Found Chrome DNS settings, resetting..."
                        
                        # Replace all DNS over HTTPS settings
                        $content = $content -replace '"dns_over_https":\s*{[^}]*}', '"dns_over_https": { "enabled": false }'
                        $content = $content -replace '"use_dns_https_sockets":\s*true', '"use_dns_https_sockets": false'
                        $content = $content -replace '"dns_over_https_servers":\s*\[[^\]]*\]', '"dns_over_https_servers": []'
                        $content = $content -replace '"secure_dns":\s*{[^}]*}', '"secure_dns": { "enabled": false }'
                        $content = $content -replace '"doh_templates":\s*\[[^\]]*\]', '"doh_templates": []'
                        
                        # Additional protection against Gamban DNS settings
                        $content = $content -replace '"template":"https://dns\.gamban\.com[^"]*"', '"template":""'
                        
                        if ($content -ne $originalContent) {
                            $modified = $true
                        }
                    }
                    
                    # If we modified something, write it back
                    if ($modified) {
                        Set-Content -Path $path -Value $content -Force -ErrorAction Stop
                        Write-ColorOutput Green "Reset Chrome DNS settings in: $path"
                    } else {
                        Write-ColorOutput Green "No custom DNS settings found in Chrome configuration file: $file"
                    }
                }
                catch {
                    Write-ColorOutput Red "Failed to modify Chrome settings: $_"
                }
            }
        }
    }
    
    # Check for Chrome policies in registry
    Write-ColorOutput Yellow "Checking for Chrome DNS policies in registry..."
    $policyPaths = @(
        "HKLM:\SOFTWARE\Policies\Google\Chrome",
        "HKCU:\SOFTWARE\Policies\Google\Chrome"
    )
    
    foreach ($policyPath in $policyPaths) {
        if (Test-Path $policyPath) {
            Write-ColorOutput Yellow "Found Chrome policy at: $policyPath"
            
            # Check for DNS-related policies
            $dnsKeys = @(
                "DnsOverHttpsMode",
                "DnsOverHttpsTemplates",
                "SecureDnsMode",
                "SecureDnsTemplates"
            )
            
            foreach ($key in $dnsKeys) {
                try {
                    if (Get-ItemProperty -Path $policyPath -Name $key -ErrorAction SilentlyContinue) {
                        Remove-ItemProperty -Path $policyPath -Name $key -Force -ErrorAction Stop
                        Write-ColorOutput Green "Removed Chrome DNS policy: $key"
                    }
                } catch {
                    Write-ColorOutput Red "Failed to remove Chrome DNS policy: $_"
                }
            }
        }
    }
    
    # Clear Chrome DNS cache
    Write-ColorOutput Yellow "Killing Chrome processes to clear DNS cache..."
    try {
        Get-Process -Name "chrome" -ErrorAction SilentlyContinue | ForEach-Object {
            $_ | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-ColorOutput Green "Terminated Chrome process: $($_.Id)"
        }
    } catch {
        Write-ColorOutput Red "Failed to terminate Chrome processes: $_"
    }
}
catch {
    Write-ColorOutput Red "Error checking Chrome DNS settings: $_"
}

# Firefox DNS settings
try {
    Write-ColorOutput Yellow "Checking for Firefox DNS settings..."
    $firefoxProfilesPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    
    if (Test-Path $firefoxProfilesPath) {
        $profiles = Get-ChildItem -Path $firefoxProfilesPath -Directory
        
        foreach ($profile in $profiles) {
            $prefsPath = Join-Path $profile.FullName "prefs.js"
            
            if (Test-Path $prefsPath) {
                Write-ColorOutput Yellow "Found Firefox preferences at: $prefsPath"
                try {
                    # Backup the file first
                    Copy-Item -Path $prefsPath -Destination "$prefsPath.backup" -Force -ErrorAction Stop
                    Write-ColorOutput Green "Created backup at: $prefsPath.backup"
                    
                    # Read the file content
                    $content = Get-Content -Path $prefsPath -ErrorAction Stop
                    
                    # Check for DNS over HTTPS settings and Gamban DNS
                    $dnsLines = $content | Where-Object { 
                        $_ -match "network\.trr\." -or 
                        $_ -match "dns\.gamban\.com" -or
                        $_ -match "network\.security\.esni\.enabled" -or
                        $_ -match "security\.tls\.enable" -or
                        $_ -match "network\.dns\." -or
                        $_ -match "doh\-rollout"
                    }
                    
                    if ($dnsLines) {
                        Write-ColorOutput Yellow "Found Firefox DNS settings, resetting..."
                        
                        # Create a new content without the DNS settings
                        $newContent = $content | Where-Object { 
                            $_ -notmatch "network\.trr\." -and 
                            $_ -notmatch "dns\.gamban\.com" -and
                            $_ -notmatch "doh-rollout\.uri" -and
                            $_ -notmatch "network\.dns\." -and
                            $_ -notmatch "network\.security\.esni\.enabled" -and
                            $_ -notmatch "network\.security\.dns"
                        }
                        
                        # Add lines to explicitly disable DNS over HTTPS and reset DNS settings
                        $newContent += 'user_pref("network.trr.mode", 0);'
                        $newContent += 'user_pref("network.trr.uri", "");'
                        $newContent += 'user_pref("network.trr.custom_uri", "");'
                        $newContent += 'user_pref("doh-rollout.uri", "");'
                        $newContent += 'user_pref("doh-rollout.provider-steering.enabled", false);'
                        $newContent += 'user_pref("network.dns.disablePrefetch", false);'
                        $newContent += 'user_pref("network.trr.resolvers", "");'
                        $newContent += 'user_pref("network.trr.confirmation_telemetry_enabled", false);'
                        $newContent += 'user_pref("network.security.dns.disabled", false);'
                        $newContent += 'user_pref("network.security.esni.enabled", false);'
                        
                        # Write the modified content back
                        Set-Content -Path $prefsPath -Value $newContent -Force -ErrorAction Stop
                        Write-ColorOutput Green "Reset Firefox DNS settings in: $prefsPath"
                        
                        # Also check for and modify prefs.js.moztmp if it exists
                        $tmpPrefsPath = Join-Path $profile.FullName "prefs.js.moztmp"
                        if (Test-Path $tmpPrefsPath) {
                            Write-ColorOutput Yellow "Found Firefox temporary preferences at: $tmpPrefsPath"
                            Copy-Item -Path $tmpPrefsPath -Destination "$tmpPrefsPath.backup" -Force -ErrorAction Stop
                            $tmpContent = Get-Content -Path $tmpPrefsPath -ErrorAction Stop
                            $newTmpContent = $tmpContent | Where-Object { 
                                $_ -notmatch "network\.trr\." -and 
                                $_ -notmatch "dns\.gamban\.com" -and
                                $_ -notmatch "doh-rollout\.uri" -and
                                $_ -notmatch "network\.dns\."
                            }
                            $newTmpContent += 'user_pref("network.trr.mode", 0);'
                            $newTmpContent += 'user_pref("network.trr.uri", "");'
                            $newTmpContent += 'user_pref("network.trr.custom_uri", "");'
                            $newTmpContent += 'user_pref("doh-rollout.uri", "");'
                            $newTmpContent += 'user_pref("network.dns.disablePrefetch", false);'
                            Set-Content -Path $tmpPrefsPath -Value $newTmpContent -Force -ErrorAction Stop
                            Write-ColorOutput Green "Reset Firefox DNS settings in temporary file: $tmpPrefsPath"
                        }
                    }
                    else {
                        Write-ColorOutput Green "No custom DNS settings found in Firefox configuration."
                    }
                    
                    # Additionally check for user.js file which can override prefs.js
                    $userJsPath = Join-Path $profile.FullName "user.js"
                    if (Test-Path $userJsPath) {
                        Write-ColorOutput Yellow "Found Firefox user.js at: $userJsPath"
                        Copy-Item -Path $userJsPath -Destination "$userJsPath.backup" -Force -ErrorAction Stop
                        $userJsContent = Get-Content -Path $userJsPath -ErrorAction Stop
                        $newUserJsContent = $userJsContent | Where-Object { 
                            $_ -notmatch "network\.trr\." -and 
                            $_ -notmatch "dns\.gamban\.com" -and
                            $_ -notmatch "doh-rollout\.uri" -and
                            $_ -notmatch "network\.dns\."
                        }
                        Set-Content -Path $userJsPath -Value $newUserJsContent -Force -ErrorAction Stop
                        Write-ColorOutput Green "Reset Firefox DNS settings in user.js: $userJsPath"
                    }
                }
                catch {
                    Write-ColorOutput Red "Failed to modify Firefox settings: $_"
                }
            }
        }
    }
    else {
        Write-ColorOutput Yellow "Firefox profiles directory not found."
    }
    
    # Also check for Mozilla configuration file that might contain DNS settings
    $mozillaConfigPath = "$env:ProgramFiles\Mozilla Firefox\defaults\pref"
    if (Test-Path $mozillaConfigPath) {
        $configFiles = Get-ChildItem -Path $mozillaConfigPath -Filter "*.js" -ErrorAction SilentlyContinue
        foreach ($file in $configFiles) {
            try {
                $content = Get-Content -Path $file.FullName -ErrorAction Stop
                if ($content -match "dns\.gamban\.com" -or $content -match "network\.trr\.") {
                    Write-ColorOutput Yellow "Found DNS settings in Mozilla config file: $($file.FullName)"
                    Copy-Item -Path $file.FullName -Destination "$($file.FullName).backup" -Force -ErrorAction Stop
                    $newContent = $content | Where-Object { 
                        $_ -notmatch "network\.trr\." -and 
                        $_ -notmatch "dns\.gamban\.com" -and
                        $_ -notmatch "doh-rollout\.uri" -and
                        $_ -notmatch "network\.dns\."
                    }
                    Set-Content -Path $file.FullName -Value $newContent -Force -ErrorAction Stop
                    Write-ColorOutput Green "Reset DNS settings in Mozilla config file: $($file.FullName)"
                }
            }
            catch {
                Write-ColorOutput Red "Failed to check/modify Mozilla config file: $_"
            }
        }
    }
}
catch {
    Write-ColorOutput Red "Error checking Firefox DNS settings: $_"
}

# Edge DNS settings (similar to Chrome as they're both Chromium-based)
try {
    Write-ColorOutput Yellow "Checking for Edge DNS settings..."
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Secure Preferences"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            Write-ColorOutput Yellow "Found Edge settings at: $path"
            try {
                # Backup the file first
                Copy-Item -Path $path -Destination "$path.backup" -Force -ErrorAction Stop
                Write-ColorOutput Green "Created backup at: $path.backup"
                
                # Read the file content
                $content = Get-Content -Path $path -Raw -ErrorAction Stop
                
                # Check if DNS settings exist and modify them
                if ($content -match '"dns_over_https"' -or $content -match '"use_dns_https_sockets"' -or $content -match '"dns_over_https_servers"') {
                    Write-ColorOutput Yellow "Found Edge DNS settings, resetting..."
                    
                    # Replace DNS over HTTPS settings
                    $content = $content -replace '"dns_over_https":\s*{[^}]*}', '"dns_over_https": { "enabled": false }'
                    $content = $content -replace '"use_dns_https_sockets":\s*true', '"use_dns_https_sockets": false'
                    $content = $content -replace '"dns_over_https_servers":\s*\[[^\]]*\]', '"dns_over_https_servers": []'
                    
                    # Write the modified content back
                    Set-Content -Path $path -Value $content -Force -ErrorAction Stop
                    Write-ColorOutput Green "Reset Edge DNS settings in: $path"
                }
                else {
                    Write-ColorOutput Green "No custom DNS settings found in Edge configuration."
                }
            }
            catch {
                Write-ColorOutput Red "Failed to modify Edge settings: $_"
            }
        }
    }
}
catch {
    Write-ColorOutput Red "Error checking Edge DNS settings: $_"
}

Write-ColorOutput Green "Browser DNS settings have been checked and reset where found."

Write-ColorOutput Green "Gamban uninstallation process completed."
Write-ColorOutput Green "It is recommended to restart your computer to ensure all components are fully removed."
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
