# Security Tool with GUI
# Main functions: Malware/Spyware detection, Device protection, System Updates, Security Hardening

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create output folder if it doesn't exist
$outputFolder = "$env:USERPROFILE\Desktop\CYBER"
if (-not (Test-Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory | Out-Null
}

# Log file
$logFile = "$outputFolder\security_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $logFile -Value $logEntry
    return $logEntry
}

function Update-ProgressBar {
    param (
        [int]$PercentComplete,
        [string]$StatusText
    )
    
    $progressBar.Value = $PercentComplete
    $statusLabel.Text = $StatusText
    $form.Refresh()
}

function Get-AvailableUpdates {
    Write-Log "Checking for available updates..."
    Update-ProgressBar -PercentComplete 10 -StatusText "Checking for Windows updates..."
    
    try {
        # Use Windows Update API to check for updates
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResults = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        Update-ProgressBar -PercentComplete 100 -StatusText "Found $($searchResults.Updates.Count) updates available."
        
        $updates = @()
        foreach ($update in $searchResults.Updates) {
            $updates += [PSCustomObject]@{
                Title = $update.Title
                Size = if ($update.MaxDownloadSize) { "$([Math]::Round($update.MaxDownloadSize / 1MB, 2)) MB" } else { "Unknown" }
                Date = if ($update.LastDeploymentChangeTime) { $update.LastDeploymentChangeTime } else { "Unknown" }
            }
        }
        
        return $updates
    }
    catch {
        Write-Log "Error checking for updates: $_" -Level "ERROR"
        Update-ProgressBar -PercentComplete 100 -StatusText "Error checking for updates."
        return @()
    }
}

function Install-AllUpdates {
    Write-Log "Installing all available updates..."
    Update-ProgressBar -PercentComplete 10 -StatusText "Preparing to install updates..."
    
    try {
        # Use Windows Update API to install updates
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResults = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        
        if ($searchResults.Updates.Count -eq 0) {
            Update-ProgressBar -PercentComplete 100 -StatusText "No updates available to install."
            return
        }
        
        Update-ProgressBar -PercentComplete 20 -StatusText "Found $($searchResults.Updates.Count) updates to install."
        
        $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResults.Updates) {
            if ($update.EulaAccepted -eq $false) {
                $update.AcceptEula()
            }
            $updatesToDownload.Add($update) | Out-Null
        }
        
        Update-ProgressBar -PercentComplete 30 -StatusText "Downloading updates..."
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload
        $downloadResult = $downloader.Download()
        
        Update-ProgressBar -PercentComplete 60 -StatusText "Installing updates..."
        $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResults.Updates) {
            if ($update.IsDownloaded) {
                $updatesToInstall.Add($update) | Out-Null
            }
        }
        
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToInstall
        $installResult = $installer.Install()
        
        Update-ProgressBar -PercentComplete 100 -StatusText "Installed $($updatesToInstall.Count) updates. Reboot may be required."
        
        # Check if reboot is required
        if ($installResult.RebootRequired) {
            $rebootPrompt = [System.Windows.Forms.MessageBox]::Show(
                "A system restart is required to complete the installation of updates. Would you like to restart now?",
                "Restart Required",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            
            if ($rebootPrompt -eq [System.Windows.Forms.DialogResult]::Yes) {
                Restart-Computer -Force
            }
        }
    }
    catch {
        Write-Log "Error installing updates: $_" -Level "ERROR"
        Update-ProgressBar -PercentComplete 100 -StatusText "Error installing updates."
    }
}

function Check-Spyware {
    Write-Log "Starting spyware and malware check..."
    Update-ProgressBar -PercentComplete 5 -StatusText "Starting security scan..."
    
    $findings = @()
    
    # Step 1: Check Windows Defender status
    Update-ProgressBar -PercentComplete 10 -StatusText "Checking Windows Defender status..."
    try {
        $defenderStatus = Get-MpComputerStatus
        if (-not $defenderStatus.AntivirusEnabled) {
            $findings += "Windows Defender antivirus is disabled!"
        }
        if (-not $defenderStatus.RealTimeProtectionEnabled) {
            $findings += "Windows Defender real-time protection is disabled!"
        }
        if ($defenderStatus.AntivirusSignatureAge -gt 7) {
            $findings += "Windows Defender virus definitions are more than 7 days old!"
        }
    }
    catch {
        Write-Log "Error checking Windows Defender status: $_" -Level "ERROR"
        $findings += "Could not check Windows Defender status."
    }
    
    # Step 2: Check for Windows Defender exclusions
    Update-ProgressBar -PercentComplete 20 -StatusText "Checking Windows Defender exclusions..."
    try {
        $exclusions = Get-MpPreference | Select-Object -Property ExclusionPath, ExclusionProcess, ExclusionExtension
        
        if ($exclusions.ExclusionPath -and $exclusions.ExclusionPath.Count -gt 0) {
            $findings += "Windows Defender has excluded paths: $($exclusions.ExclusionPath -join ', ')"
        }
        if ($exclusions.ExclusionProcess -and $exclusions.ExclusionProcess.Count -gt 0) {
            $findings += "Windows Defender has excluded processes: $($exclusions.ExclusionProcess -join ', ')"
        }
        if ($exclusions.ExclusionExtension -and $exclusions.ExclusionExtension.Count -gt 0) {
            $findings += "Windows Defender has excluded extensions: $($exclusions.ExclusionExtension -join ', ')"
        }
    }
    catch {
        Write-Log "Error checking Windows Defender exclusions: $_" -Level "ERROR"
        $findings += "Could not check Windows Defender exclusions."
    }
    
    # Step 3: Check for suspicious scheduled tasks
    Update-ProgressBar -PercentComplete 30 -StatusText "Checking scheduled tasks..."
    try {
        $suspiciousTasks = Get-ScheduledTask | Where-Object {
            $_.State -eq "Ready" -and (
                $_.Actions.Execute -match "powershell|cmd|wscript|cscript" -or
                $_.TaskPath -notmatch "\\Microsoft\\" -or
                $_.TaskName -match "update|helper|service" -and $_.Author -notmatch "Microsoft"
            )
        }
        
        foreach ($task in $suspiciousTasks) {
            $findings += "Suspicious scheduled task: $($task.TaskName) at $($task.TaskPath) executes $($task.Actions.Execute)"
        }
    }
    catch {
        Write-Log "Error checking scheduled tasks: $_" -Level "ERROR"
        $findings += "Could not check scheduled tasks."
    }
    
    # Step 4: Check for unusual startup programs
    Update-ProgressBar -PercentComplete 40 -StatusText "Checking startup programs..."
    try {
        $startupPrograms = Get-CimInstance Win32_StartupCommand
        
        foreach ($program in $startupPrograms) {
            if ($program.Location -notmatch "Windows|Microsoft|Intel|NVIDIA|AMD|Realtek" -and 
                $program.Command -match "powershell|cmd|wscript|cscript|.vbs|.js") {
                $findings += "Suspicious startup program: $($program.Name) at $($program.Location) runs: $($program.Command)"
            }
        }
    }
    catch {
        Write-Log "Error checking startup programs: $_" -Level "ERROR"
        $findings += "Could not check startup programs."
    }
    
    # Step 5: Check for suspicious services
    Update-ProgressBar -PercentComplete 50 -StatusText "Checking services..."
    try {
        $suspiciousServices = Get-Service | Where-Object {
            $_.Status -eq "Running" -and
            $_.DisplayName -notmatch "Windows|Microsoft|Intel|NVIDIA|AMD|Realtek" -and
            $_.DisplayName -match "remote|access|control|helper|update"
        }
        
        foreach ($service in $suspiciousServices) {
            $findings += "Suspicious service: $($service.DisplayName) [$($service.Name)]"
        }
    }
    catch {
        Write-Log "Error checking services: $_" -Level "ERROR"
        $findings += "Could not check services."
    }
    
    # Step 6: Check for suspicious network connections
    Update-ProgressBar -PercentComplete 60 -StatusText "Checking network connections..."
    try {
        $suspiciousConnections = Get-NetTCPConnection | Where-Object {
            $_.State -eq "Established" -and
            $_.RemotePort -notmatch "80|443|8080|53" -and
            $_.OwningProcess -ne 0
        }
        
        foreach ($conn in $suspiciousConnections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($process) {
                $findings += "Suspicious network connection: $($process.Name) [$($conn.OwningProcess)] connected to $($conn.RemoteAddress):$($conn.RemotePort)"
            }
        }
    }
    catch {
        Write-Log "Error checking network connections: $_" -Level "ERROR"
        $findings += "Could not check network connections."
    }
    
    # Step 7: Check for suspicious event logs
    Update-ProgressBar -PercentComplete 70 -StatusText "Checking event logs for suspicious activities..."
    try {
        # Check for failed login attempts
        $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
        if ($failedLogins -and $failedLogins.Count -gt 10) {
            $findings += "High number of failed login attempts detected: $($failedLogins.Count) in recent logs"
        }
        
        # Check for PowerShell script block logging
        $suspiciousPSCommands = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 -ErrorAction SilentlyContinue | 
            Where-Object { $_.Message -match "downloadstring|invoke-expression|iex|bypass|hidden|encoded|webclient|shellcode|mimikatz" }
        
        if ($suspiciousPSCommands) {
            foreach ($event in $suspiciousPSCommands) {
                $findings += "Suspicious PowerShell command detected at $($event.TimeCreated): $($event.Message.Substring(0, [Math]::Min(100, $event.Message.Length)))..."
            }
        }
    }
    catch {
        Write-Log "Error checking event logs: $_" -Level "ERROR"
        $findings += "Could not check event logs."
    }
    
    # Step 8: Check for potential Living Off The Land (LOTL) binaries misuse
    Update-ProgressBar -PercentComplete 80 -StatusText "Checking for LOTL techniques..."
    try {
        $lotlBinaries = @("certutil.exe", "regsvr32.exe", "mshta.exe", "wmic.exe", "bitsadmin.exe", "odbcconf.exe", "msiexec.exe")
        
        foreach ($binary in $lotlBinaries) {
            $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 100 -ErrorAction SilentlyContinue | 
                Where-Object { $_.Message -match $binary -and $_.Message -match "http|ftp|file:\/\/|\\\\|\-decode|\-urlcache" }
            
            if ($events) {
                foreach ($event in $events) {
                    $findings += "Potential LOTL technique detected: $binary used at $($event.TimeCreated)"
                }
            }
        }
    }
    catch {
        Write-Log "Error checking for LOTL techniques: $_" -Level "ERROR"
        $findings += "Could not check for LOTL techniques. Consider installing Sysmon for better detection."
    }
    
    # Step 9: Run a quick Windows Defender scan
    Update-ProgressBar -PercentComplete 90 -StatusText "Running quick malware scan..."
    try {
        Start-MpScan -ScanType QuickScan
        $scanResults = Get-MpThreatDetection
        
        if ($scanResults) {
            foreach ($threat in $scanResults) {
                $findings += "Malware detected: $($threat.ThreatName) in $($threat.Resources)"
            }
        }
    }
    catch {
        Write-Log "Error running malware scan: $_" -Level "ERROR"
        $findings += "Could not run malware scan."
    }
    
    Update-ProgressBar -PercentComplete 100 -StatusText "Security scan complete."
    
    if ($findings.Count -eq 0) {
        $findings += "No suspicious activities or malware detected."
    }
    
    Write-Log "Security scan completed with $($findings.Count) findings."
    return $findings
}

function Harden-PC {
    Write-Log "Starting PC hardening process..."
    Update-ProgressBar -PercentComplete 10 -StatusText "Starting security hardening..."
    
    $hardeningResults = @()
    
    # Step 1: Check if regular user exists, if not create one
    Update-ProgressBar -PercentComplete 20 -StatusText "Checking user accounts..."
    try {
        $regularUserExists = Get-LocalUser -Name "DOMA" -ErrorAction SilentlyContinue
        
        if (-not $regularUserExists) {
            $password = ConvertTo-SecureString -String "ChangeMe123!" -AsPlainText -Force
            New-LocalUser -Name "DOMA" -Password $password -FullName "Domaci Uzivatel" -Description "Regular user account" -AccountNeverExpires
            Add-LocalGroupMember -Group "Users" -Member "DOMA"
            
            $hardeningResults += "Created new regular user account 'DOMA'. Please change the initial password."
            
            [System.Windows.Forms.MessageBox]::Show(
                "Prosim pouzivejte uzivatelky ucet 'DOMA' pro bezne pouziti.",
                "Informace",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        else {
            $hardeningResults += "Regular user account 'DOMA' already exists."
        }
    }
    catch {
        Write-Log "Error checking/creating regular user: $_" -Level "ERROR"
        $hardeningResults += "Failed to check or create regular user account."
    }
    
    # Step 2: Enable PowerShell and Command Line Logging
    Update-ProgressBar -PercentComplete 30 -StatusText "Enabling PowerShell and CMD logging..."
    try {
        # Enable PowerShell Script Block Logging
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWORD -Force
        
        # Enable PowerShell Module Logging
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWORD -Force
        
        # Enable Command Line Process Auditing
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
        
        # Enable PowerShell Transcription
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWORD -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWORD -Force
        
        $transcriptPath = "$env:USERPROFILE\Desktop\CYBER\PowerShellLogs"
        if (-not (Test-Path $transcriptPath)) {
            New-Item -Path $transcriptPath -ItemType Directory | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value $transcriptPath -Type String -Force
        
        $hardeningResults += "Enabled PowerShell and command line logging."
    }
    catch {
        Write-Log "Error enabling PowerShell and CMD logging: $_" -Level "ERROR"
        $hardeningResults += "Failed to enable PowerShell and command line logging."
    }
    
    # Step 3: Configure additional security audit policies
    Update-ProgressBar -PercentComplete 40 -StatusText "Configuring audit policies..."
    try {
        # Audit account logon events
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
        auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
        
        # Audit directory service access
        auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
        
        # Audit object access
        auditpol /set /subcategory:"File System" /success:enable /failure:enable
        auditpol /set /subcategory:"Registry" /success:enable /failure:enable
        
        # Audit policy change
        auditpol /set /subcategory:"Security Policy Change" /success:enable /failure:enable
        auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
        
        # Audit privilege use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
        
        # Audit system events
        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
        
        $hardeningResults += "Configured enhanced audit policies."
    }
    catch {
        Write-Log "Error configuring audit policies: $_" -Level "ERROR"
        $hardeningResults += "Failed to configure audit policies."
    }
    
    # Step 4: Enable Windows Defender Advanced Features
    Update-ProgressBar -PercentComplete 50 -StatusText "Configuring Windows Defender..."
    try {
        # Enable real-time protection
        Set-MpPreference -DisableRealtimeMonitoring $false
        
        # Enable cloud-based protection
        Set-MpPreference -MAPSReporting Advanced
        
        # Enable network protection
        Set-MpPreference -EnableNetworkProtection Enabled
        
        # Enable controlled folder access
        Set-MpPreference -EnableControlledFolderAccess Enabled
        
        # Enable attack surface reduction rules
        Set-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
        
        $hardeningResults += "Enhanced Windows Defender security settings."
    }
    catch {
        Write-Log "Error configuring Windows Defender: $_" -Level "ERROR"
        $hardeningResults += "Failed to configure Windows Defender."
    }
    
    # Step 5: Disable unnecessary services
    Update-ProgressBar -PercentComplete 60 -StatusText "Disabling unnecessary services..."
    try {
        $unnecessaryServices = @(
            "RemoteAccess",
            "RemoteRegistry",
            "SharedAccess",
            "Fax",
            "TapiSrv",
            "UPnPHost",
            "WebClient"
        )
        
        foreach ($service in $unnecessaryServices) {
            if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                $hardeningResults += "Disabled unnecessary service: $service"
            }
        }
    }
    catch {
        Write-Log "Error disabling unnecessary services: $_" -Level "ERROR"
        $hardeningResults += "Failed to disable some unnecessary services."
    }
    
    # Step 6: Configure Windows Firewall
    Update-ProgressBar -PercentComplete 70 -StatusText "Configuring Windows Firewall..."
    try {
        # Enable Windows Firewall for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        # Block outbound connections by default (requires explicit rules for allowed outbound traffic)
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block
        
        # Allow common outbound traffic
        New-NetFirewallRule -DisplayName "Allow Web Browsing" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80,443 -Program "Any" -Enabled True
        New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Program "Any" -Enabled True
        New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 67,68 -Program "Any" -Enabled True
        
        $hardeningResults += "Configured Windows Firewall with enhanced security."
    }
    catch {
        Write-Log "Error configuring Windows Firewall: $_" -Level "ERROR"
        $hardeningResults += "Failed to configure Windows Firewall."
    }
    
    # Step 7: Enable Device Guard and Credential Guard (if hardware supports)
    Update-ProgressBar -PercentComplete 80 -StatusText "Configuring advanced protections..."
    try {
        # Check if virtualization-based security is available
        $vbsSupported = Get-ComputerInfo | Select-Object -ExpandProperty HyperVisorPresent
        
        if ($vbsSupported) {
            # Enable Device Guard
            $devGuardRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            if (-not (Test-Path $devGuardRegistryPath)) {
                New-Item -Path $devGuardRegistryPath -Force | Out-Null
            }
            Set-ItemProperty -Path $devGuardRegistryPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWORD
            Set-ItemProperty -Path $devGuardRegistryPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWORD
            
            # Enable Credential Guard
            $credGuardRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            if (-not (Test-Path $credGuardRegistryPath)) {
                New-Item -Path $credGuardRegistryPath -Force | Out-Null
            }
            Set-ItemProperty -Path $credGuardRegistryPath -Name "LsaCfgFlags" -Value 1 -Type DWORD
            
            $hardeningResults += "Enabled Device Guard and Credential Guard (restart required)."
        }
        else {
            $hardeningResults += "Device Guard and Credential Guard not enabled (hardware does not support virtualization)."
        }
    }
    catch {
        Write-Log "Error configuring Device Guard and Credential Guard: $_" -Level "ERROR"
        $hardeningResults += "Failed to configure Device Guard and Credential Guard."
    }
    
    # Step 8: Set UAC to highest level
    Update-ProgressBar -PercentComplete 90 -StatusText "Configuring user access control..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
        
        $hardeningResults += "Set User Account Control (UAC) to highest level."
    }
    catch {
        Write-Log "Error configuring UAC: $_" -Level "ERROR"
        $hardeningResults += "Failed to configure User Account Control settings."
    }
    
    Update-ProgressBar -PercentComplete 100 -StatusText "Security hardening complete."
    Write-Log "Security hardening completed with $($hardeningResults.Count) changes."
    
    return $hardeningResults
}

function Add-ToSIEM {
    Write-Log "Setting up SIEM integration..."
    Update-ProgressBar -PercentComplete 10 -StatusText "Setting up SIEM integration..."
    
    $siemResults = @()
    
    # Create configuration file for SIEM connector
    try {
        $siemConfigPath = "$outputFolder\siem_config.xml"
        
        $siemConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<SIEMConfiguration>
    <General>
        <ComputerName>$env:COMPUTERNAME</ComputerName>
        <Domain>$env:USERDOMAIN</Domain>
        <IPAddress>$((Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet*" | Select-Object -First 1).IPAddress)</IPAddress>
        <RegisteredAt>$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</RegisteredAt>
    </General>
    <ForwardedLogs>
        <LogType Name="Security" Enabled="true" />
        <LogType Name="System" Enabled="true" />
        <LogType Name="Application" Enabled="true" />
        <LogType Name="Microsoft-Windows-PowerShell/Operational" Enabled="true" />
        <LogType Name="Microsoft-Windows-Sysmon/Operational" Enabled="true" />
        <LogType Name="Microsoft-Windows-Windows Defender/Operational" Enabled="true" />
    </ForwardedLogs>
    <SIEMServer>
        <ServerAddress>siem.example.com</ServerAddress>
        <Protocol>SYSLOG</Protocol>
        <Port>514</Port>
        <UseTLS>true</UseTLS>
    </SIEMServer>
</SIEMConfiguration>
"@
        
        Set-Content -Path $siemConfigPath -Value $siemConfigContent
        $siemResults += "Created SIEM configuration file at $siemConfigPath"
        
        Update-ProgressBar -PercentComplete 30 -StatusText "Enabling Windows Event Forwarding..."
        
        # Enable Windows Event Collector service
        Set-Service -Name Wecsvc -StartupType Automatic
        Start-Service -Name Wecsvc
        $siemResults += "Enabled Windows Event Collector service"
        
        # Configure Windows Event Forwarding
        $wefPath = "$outputFolder\wef_config.xml"
        $wefContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Subscription xmlns="http://schemas.microsoft.com/2
