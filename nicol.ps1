#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Bezpečnostní skript pro aktualizaci, kontrolu a hardening Windows stanice s rozšířenou detekcí.
.DESCRIPTION
    Skript provádí následující kroky:
    1. Aktualizuje systém a aplikace.
    2. Kontroluje bezpečnostní nastavení, včetně rozšířené kontroly na spyware/infostealery.
    3. Provádí hardening stanice, včetně specifické logiky pro vytvoření uživatele "DOMA" a nasazení canary tokenu.
    ... (zbytek popisu jako dříve)
.NOTES
    Autor: Vitruvius
    Verze: 1.2
    Vyžaduje spuštění jako Administrátor.
    Před použitím důkladně otestujte v bezpečném prostředí!
    Funkce canary tokenu závisí na externí službě canarytokens.org.
#>

# --- Globální proměnné a nastavení ---
$Global:findings = [System.Collections.Generic.List[string]]::new()
$Global:uncertainties = [System.Collections.Generic.List[string]]::new()
$Global:logEntries = [System.Collections.Generic.List[string]]::new()
$Global:startTime = Get-Date
$Global:scriptMode = "" 
Set-StrictMode -Version Latest

# --- Pomocné funkce pro logování a potvrzování ---
# ... (funkce Add-Log, Add-Finding, Confirm-Action beze změny z verze 1.1) ...
function Add-Log {
    param(
        [string]$Message,
        [string]$Type = "INFO" # INFO, WARNING, ERROR, FINDING, DEBUG
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Type] $Message"
    $Global:logEntries.Add($logLine)
    Write-Host $logLine
    if ($Type -eq "ERROR") {
        Write-Host $logLine -ForegroundColor Red
    } elseif ($Type -eq "WARNING") {
        Write-Host $logLine -ForegroundColor Yellow
    } elseif ($Type -eq "DEBUG") {
        Write-Host $logLine -ForegroundColor Cyan
    }
}

function Add-Finding {
    param(
        [string]$Message,
        [bool]$IsUncertainty = $false
    )
    $Global:findings.Add($Message)
    if ($IsUncertainty) {
        $Global:uncertainties.Add($Message)
    }
    Add-Log -Message "NÁLEZ: $Message" -Type "FINDING"
}

function Confirm-Action {
    param (
        [string]$Message
    )
    if ($Global:scriptMode -eq "Interactive") {
        while ($true) {
            $choice = Read-Host "$Message (Ano/Ne/Přeskočit)"
            if ($choice -match '^(a|ano)$') { return "Yes" }
            if ($choice -match '^(n|ne)$') { return "No" }
            if ($choice -match '^(p|přeskočit|preskocit)$') { return "Skip" }
            Write-Warning "Neplatná volba. Zadejte 'Ano', 'Ne' nebo 'Přeskočit'."
        }
    }
    return "Yes" # V autonomním režimu vždy Ano (po úvodním potvrzení)
}


# --- Sekce 1: Aktualizace ---
function Update-System {
    # ... (kód beze změny z verze 1.1) ...
    Add-Log "--- ZAČÁTEK SEKCE: Aktualizace systému ---" -Type "DEBUG"
    $overallAction = Confirm-Action "Chcete provést aktualizaci systému a aplikací?"
    if ($overallAction -eq "No") { Add-Log "Uživatel odmítl aktualizace."; return }
    if ($overallAction -eq "Skip") { Add-Log "Sekce aktualizací byla přeskočena."; return }

    $action = Confirm-Action "Chcete vyhledat a nainstalovat aktualizace Windows?"
    if ($action -eq "Yes") {
        Add-Log "Kontrola modulu PSWindowsUpdate..."
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Add-Log "Modul PSWindowsUpdate není nainstalován. Pokouším se nainstalovat..."
            try {
                Install-Module PSWindowsUpdate -Force -SkipPublisherCheck -Scope AllUsers -ErrorAction Stop
                Import-Module PSWindowsUpdate -Force
                Add-Log "Modul PSWindowsUpdate úspěšně nainstalován a importován."
            } catch {
                Add-Log "Chyba při instalaci modulu PSWindowsUpdate: $($_.Exception.Message)" -Type "ERROR"
                Add-Finding "Nepodařilo se nainstalovat modul PSWindowsUpdate pro aktualizace Windows." $true
            }
        } else {
            Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue 
            Add-Log "Modul PSWindowsUpdate je již nainstalován."
        }

        if (Get-Module -Name PSWindowsUpdate) {
            Add-Log "Vyhledávání a instalace aktualizací Windows..."
            try {
                Get-WindowsUpdate -Install -AcceptAll -Verbose -ErrorAction SilentlyContinue | Out-Null
                $RebootRequired = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) -ne $null
                if ($RebootRequired) {
                    Add-Finding "Po instalaci aktualizací Windows je vyžadován restart počítače."
                    if ((Confirm-Action "Je vyžadován restart. Chcete restartovat nyní?") -eq "Yes") {
                        Restart-Computer -Force
                    }
                } else {
                    Add-Log "Aktualizace Windows dokončeny (nebo žádné nebyly k dispozici)."
                }
            } catch {
                Add-Log "Chyba při aktualizaci Windows: $($_.Exception.Message)" -Type "ERROR"
                Add-Finding "Došlo k chybě během procesu Windows Update." $true
            }
        } else {
             Add-Log "Modul PSWindowsUpdate není dostupný. Přeskakuji Windows Update." -Type "WARNING"
        }
    } elseif ($action -eq "Skip") { Add-Log "Aktualizace Windows přeskočeny." }

    $action = Confirm-Action "Chcete aktualizovat aplikace pomocí Winget?"
    if ($action -eq "Yes") {
        Add-Log "Aktualizace aplikací pomocí Winget..."
        $wingetExe = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetExe) {
            try {
                Add-Log "Spouštím: winget upgrade --all --include-unknown --accept-package-agreements --accept-source-agreements"
                if ($Global:scriptMode -eq "Interactive") {
                     winget upgrade --all --include-unknown --verbose 
                } else {
                     winget upgrade --all --silent --include-unknown --accept-package-agreements --accept-source-agreements --verbose
                }
                Add-Log "Aktualizace pomocí Winget dokončeny."
            } catch {
                Add-Log "Chyba při aktualizaci pomocí Winget: $($_.Exception.ToString())" -Type "ERROR"
                Add-Finding "Došlo k chybě během aktualizace aplikací přes Winget." $true
            }
        } else {
            Add-Log "Příkaz 'winget' nebyl nalezen. Přeskočeno." -Type "WARNING"
            Add-Finding "Winget nebyl nalezen, některé aplikace nemusí být aktualizovány."
        }
    } elseif ($action -eq "Skip") { Add-Log "Aktualizace přes Winget přeskočeny." }

    if (Get-Command choco -ErrorAction SilentlyContinue) {
        $action = Confirm-Action "Chcete aktualizovat balíčky pomocí Chocolatey?"
        if ($action -eq "Yes") {
            Add-Log "Aktualizace balíčků pomocí Chocolatey..."
            try {
                if ($Global:scriptMode -eq "Interactive") {
                    choco upgrade all
                } else {
                    choco upgrade all -y --no-progress
                }
                Add-Log "Aktualizace pomocí Chocolatey dokončeny."
            } catch {
                Add-Log "Chyba při aktualizaci pomocí Chocolatey: $($_.Exception.Message)" -Type "ERROR"
                Add-Finding "Došlo k chybě během aktualizace balíčků přes Chocolatey." $true
            }
        } elseif ($action -eq "Skip") { Add-Log "Aktualizace přes Chocolatey přeskočeny." }
    }

    $action = Confirm-Action "Chcete se pokusit spustit vyhledávání aktualizací pro aplikace z Microsoft Store?"
    if ($action -eq "Yes") {
        Add-Log "Pokus o spuštění vyhledávání aktualizací pro Microsoft Store aplikace..."
        try {
            Add-Log "Tato akce pouze signalizuje systému, aby zkontroloval aktualizace. Skutečné stahování a instalace probíhá na pozadí nebo vyžaduje interakci v Microsoft Store."
            (Get-CimInstance -Namespace "root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" -ErrorAction SilentlyContinue | Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction SilentlyContinue) | Out-Null
            Add-Log "Příkaz pro vyhledávání aktualizací Microsoft Store aplikací byl odeslán. Zkontrolujte Microsoft Store manuálně pro stav."
        } catch {
            Add-Log "Nepodařilo se spustit vyhledávání aktualizací pro Microsoft Store: $($_.Exception.Message)" -Type "WARNING"
        }
        Add-Log "Doporučuje se také manuálně zkontrolovat Microsoft Store pro aktualizace aplikací."
    } elseif ($action -eq "Skip") { Add-Log "Aktualizace Microsoft Store aplikací přeskočeny." }
    Add-Log "--- KONEC SEKCE: Aktualizace systému ---" -Type "DEBUG"
}

# --- Sekce 2: Kontrola bezpečnostních nastavení a auditů ---
function Check-SecuritySettings {
    Add-Log "--- ZAČÁTEK SEKCE: Kontrola bezpečnostních nastavení ---" -Type "DEBUG"
    $overallAction = Confirm-Action "Chcete provést kontrolu bezpečnostních nastavení a auditů (včetně rozšířené detekce)?"
    if ($overallAction -eq "No") { Add-Log "Uživatel odmítl kontrolu bezpečnostních nastavení."; return }
    if ($overallAction -eq "Skip") { Add-Log "Sekce kontroly bezpečnostních nastavení byla přeskočena."; return }

    # ... (Kontrola uživatelských účtů, UAC, Auditní logy - kód z verze 1.1) ...
    Add-Log "Kontrola uživatelských účtů..."
    $adminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, PrincipalSource, SID, ObjectClass
    Add-Log "Účty ve skupině Administrators:"
    $adminUsers | ForEach-Object { Add-Log "  - $($_.Name) (Zdroj: $($_.PrincipalSource), Typ: $($_.ObjectClass))" }
    if (($adminUsers | Where-Object {$_.PrincipalSource -eq "Local" -and $_.ObjectClass -eq "User"}).Count -gt 2) {
        Add-Finding "Nalezeno více než 2 lokální uživatelské účty ve skupině Administrators. Zvažte jejich redukci." $true
    }
    # ... zbytek kontroly uživatelů ...

    Add-Log "Kontrola stavu User Account Control (UAC)..."
    try {
        $uacEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction Stop).EnableLUA
        if ($uacEnabled -eq 1) { Add-Log "UAC (EnableLUA) je povoleno." }
        else { Add-Finding "UAC (EnableLUA) je zakázáno! Doporučuje se povolit UAC." $true }
    } catch { # ... ošetření chyby ... 
        Add-Log "Nepodařilo se zjistit stav UAC (EnableLUA): $($_.Exception.Message)" -Type "ERROR"
        Add-Finding "Nepodařilo se zjistit stav UAC (EnableLUA)." $true
    }

    Add-Log "Kontrola auditních logů (poslední záznamy a nedávné chyby/varování)..."
    $logNames = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")
    foreach ($logName in $logNames) {
        # ... (kontrola logů jako v předchozí verzi) ...
        try {
            $latestEntry = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($latestEntry) { Add-Log "Poslední záznam v logu '$logName': $($latestEntry.TimeCreated)" }
            else { Add-Log "Log '$logName' je prázdný nebo neexistuje." -Type "WARNING" }

            $recentProblems = Get-WinEvent -FilterHashtable @{LogName=$logName; Level=1,2,3} -MaxEvents 20 -ErrorAction SilentlyContinue
            if ($recentProblems.Count -gt 0) {
                Add-Finding "Nalezeno $($recentProblems.Count) nedávných chyb/varování v logu '$logName'. Doporučuje se manuální kontrola." $true
                $Global:uncertainties.Add("Prozkoumejte chyby/varování v logu '$logName'. Několik posledních:")
                $recentProblems | Select-Object -First 5 TimeCreated, ID, LevelDisplayName, Message | Format-List | Out-String | ForEach-Object {$Global:uncertainties.Add($_)}
            }
        } catch { Add-Log "Chyba při čtení logu '$logName': $($_.Exception.Message)" -Type "ERROR" }
    }
    # ... (kontrola auditních politik jako v předchozí verzi) ...
    try {
        $auditCategories = @{ "Logon" = "Logon"; "Process Creation" = "Detailed Tracking" }
        foreach ($subCategory in $auditCategories.Keys) {
            $auditSetting = auditpol /get /subcategory:$subCategory /r | ConvertFrom-Csv -ErrorAction SilentlyContinue
            if ($auditSetting) {
                 $settingStatus = $auditSetting | Select-Object -ExpandProperty "Inclusion Setting"
                 Add-Log "Audit Policy pro Subcategory '$subCategory': $settingStatus"
                 if (($subCategory -eq "Logon" -or $subCategory -eq "Process Creation") -and $settingStatus -notmatch "Success and Failure" -and $settingStatus -notmatch "Success") {
                     Add-Finding "Auditování '$subCategory' není nastaveno alespoň na 'Success'. Doporučeno 'Success and Failure'. Aktuálně: '$settingStatus'." $true
                 }
            } else { Add-Log "Nepodařilo se získat Audit Policy pro Subcategory '$subCategory'." -Type "WARNING" }
        }
    } catch { Add-Log "Nepodařilo se zkontrolovat politiky auditování pomocí auditpol: $($_.Exception.Message)" -Type "WARNING" }


    Add-Log "ROZŠÍŘENÉ HLEDÁNÍ SPYWARE/INFOSTEALERŮ..."

    # 2.4.1 Kontrola souboru hosts
    Add-Log "Kontrola souboru hosts..."
    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        try {
            $hostsContent = Get-Content $hostsFile -ErrorAction Stop
            $suspiciousEntries = $hostsContent | Where-Object { $_ -match "^\s*([0-9\.]+|[0-9a-fA-F:]+)\s+([\w\.\-]+)" -and $_ -notmatch "^\s*#" -and $_ -notmatch "127\.0\.0\.1" -and $_ -notmatch "::1" }
            if ($suspiciousEntries) {
                Add-Finding "Nalezeny potenciálně podezřelé (ne-lokální) záznamy v souboru hosts. Manuálně ověřte jejich legitimitu:" $true
                $suspiciousEntries | ForEach-Object { Add-Log "  - $($_)"; $Global:uncertainties.Add("Podezřelý hosts záznam: $_") }
            } else {
                Add-Log "V souboru hosts nebyly nalezeny žádné zjevně podezřelé aktivní (nekomentované, ne-lokální) záznamy."
            }
        } catch {
            Add-Log "Chyba při čtení souboru hosts: $($_.Exception.Message)" -Type "ERROR"
        }
    } else {
        Add-Log "Soubor hosts nebyl nalezen na standardní cestě." -Type "WARNING"
    }

    # 2.4.2 Kontrola PowerShell profilů
    Add-Log "Kontrola PowerShell profilů..."
    $psProfiles = @(
        try { $PROFILE.AllUsersAllHosts } catch {},
        try { $PROFILE.AllUsersCurrentHost } catch {},
        try { $PROFILE.CurrentUserAllHosts } catch {},
        try { $PROFILE.CurrentUserCurrentHost } catch {}
    ) | Where-Object {$_ -ne $null -and (Test-Path $_)}

    foreach ($profilePath in $psProfiles) {
        try {
            $profileContent = Get-Content $profilePath -Raw -ErrorAction Stop
            if ($profileContent.Length -gt 1024) { # Prahová hodnota pro "příliš velký" profil
                Add-Finding "PowerShell profil '$profilePath' je neobvykle velký ($($profileContent.Length) bajtů). Doporučuje se manuální kontrola obsahu." $true
            }
            if ($profileContent -match "Invoke-Expression|iex|FromBase64String|DownloadString|Start-Process .* -WindowStyle Hidden" ) {
                Add-Finding "PowerShell profil '$profilePath' obsahuje potenciálně podezřelá klíčová slova. Doporučuje se manuální kontrola obsahu." $true
                $Global:uncertainties.Add("Podezřelý PowerShell profil: $profilePath (obsahuje riziková klíčová slova)")
            }
        } catch {
            Add-Log "Chyba při čtení PowerShell profilu '$profilePath': $($_.Exception.Message)" -Type "WARNING"
        }
    }
    if ($psProfiles.Count -eq 0) {
        Add-Log "Nebyly nalezeny žádné existující PowerShell profily."
    }

    # 2.4.3 Kontrola nedávno změněných/vytvořených spustitelných souborů bez MS podpisu
    Add-Log "Kontrola nedávno změněných/vytvořených spustitelných souborů v uživatelských složkách..."
    $suspiciousUserPaths = @("$env:APPDATA", "$env:LOCALAPPDATA", "$env:TEMP", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents")
    $recentDateThreshold = (Get-Date).AddDays(-7)
    $suspiciousExtensions = @("*.exe", "*.dll", "*.scr", "*.vbs", "*.js", "*.ps1", "*.bat", "*.cmd", "*.jar", "*.py")
    
    foreach ($usrPath in $suspiciousUserPaths) {
        if (Test-Path $usrPath) {
            try {
                Get-ChildItem -Path $usrPath -Include $suspiciousExtensions -Recurse -ErrorAction SilentlyContinue -Force |
                    Where-Object { $_.LastWriteTime -gt $recentDateThreshold -and -not $_.PSIsContainer } |
                    ForEach-Object {
                        $file = $_
                        $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                        if (($signature -eq $null) -or ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) -or ($signature.SignerCertificate.Subject -notlike "CN=Microsoft*")) {
                            $findingMsg = "Potenciálně podezřelý nedávno změněný/vytvořený soubor: $($file.FullName) (Změněno: $($file.LastWriteTime), Podpis: $($signature.Status), Vydavatel: $($signature.SignerCertificate.SubjectDisplayName))"
                            Add-Finding $findingMsg $true
                        }
                    }
            } catch {
                Add-Log "Chyba při prohledávání cesty '$usrPath' pro nedávné soubory: $($_.Exception.Message)" -Type "WARNING"
            }
        }
    }
    
    # ... (Zbytek IOC skenu, Kontrola výjimek v Defenderu, Spuštění Defender Scanu - kód z verze 1.1) ...
    # Původní IOC sken
    Add-Log "Prohledávání specifických známých indikátorů kompromitace (IOC) - základní kontrola..."
    $suspiciousPaths = @(
        "$env:TEMP\*.exe", "$env:APPDATA\*.exe", "$env:LOCALAPPDATA\Temp\*.exe",
        "$env:USERPROFILE\Documents\*.js", "$env:USERPROFILE\Downloads\*.vbs",
        "$env:LOCALAPPDATA\Lumma\*", "$env:APPDATA\LummaStealer\*" # Příklad, může být zastaralé
    ) # ... (zbytek jako dříve) ...
    foreach ($path in $suspiciousPaths) {
        try {
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue -Recurse -Force -ea 0 | Select-Object -First 5
            if ($items) {
                $items | ForEach-Object {
                    Add-Finding "Nalezen potenciálně podezřelý soubor/složka dle starší masky IOC '$path': $($_.FullName). Doporučuje se manuální analýza." $true
                }
            }
        } catch { Add-Log "Chyba při prohledávání cesty '$path' dle starší masky IOC: $($_.Exception.Message)" -Type "WARNING" }
    }
    # ... (kontrola run keys, scheduled tasks jako dříve) ...
    $runKeys = @( "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" )
    foreach ($keyPath in $runKeys) { # ... (jako dříve) ... 
        if (Test-Path $keyPath) {
            Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | ForEach-Object {
                $_.PSObject.Properties | Where-Object {$_.Name -ne "(default)"} | ForEach-Object {
                    Add-Log "Nalezen záznam v auto-startu ($keyPath): NÁZEV: $($_.Name), HODNOTA: $($_.Value)"
                    if ($_.Value -match '[a-z0-9]{12,}\.exe' -or $_.Value -like "*\Temp\*") {
                         Add-Finding "Podezřelý záznam v auto-startu ($keyPath): NÁZEV: $($_.Name), HODNOTA: $($_.Value). Doporučuje se manuální kontrola." $true
                    }
                }
            }
        }
    }
    # ... (scheduled tasks jako dříve) ...
    Add-Log "Kontrola naplánovaných úloh (mimo Microsoft)..."
    try {
        $tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*" -and $_.State -ne "Disabled"}
        if ($tasks) {
            foreach ($task in $tasks) {
                $taskDetails = "Naplánovaná úloha: $($task.TaskName) (Cesta: $($task.TaskPath), Autor: $($task.Principal.UserID), Akce: $($task.Actions | ForEach-Object {if($_.Execute){$_.Execute + " " + $_.Arguments} else {$_.ToString()}}))"
                Add-Log $taskDetails
                if ($task.Actions.Execute -match '[a-z0-9]{12,}\.exe' -or $task.Actions.Execute -like "*\Temp\*" -or ($task.Principal.UserID -match "S-1-5-21-\d+-\d+-\d+-\d+$" -and $task.Principal.UserID -ne "S-1-5-18" -and $task.Principal.UserID -ne "S-1-5-19" -and $task.Principal.UserID -ne "S-1-5-20"))) {
                     Add-Finding "Podezřelá naplánovaná úloha: $taskDetails. Doporučuje se manuální kontrola." $true
                }
            }
        } else { Add-Log "Nebyly nalezeny žádné aktivní ne-Microsoft naplánované úlohy." }
    } catch { Add-Log "Chyba při kontrole naplánovaných úloh: $($_.Exception.Message)" -Type "ERROR" }


    Add-Log "Kontrola výjimek v Microsoft Defender Antivirus..."
    # ... (kód kontroly výjimek z verze 1.1) ...
    try {
        $exclusions = Get-MpPreference -ErrorAction SilentlyContinue
        if ($exclusions) {
            $foundExclusion = $false
            if ($exclusions.ExclusionPath.Count -gt 0) {
                Add-Finding "Nalezeny následující VÝJIMKY CEST v Defenderu. Zkontrolujte jejich legitimitu:" $true
                $exclusions.ExclusionPath | ForEach-Object { Add-Log "  - Cesta: $_"; $Global:uncertainties.Add("Defender Výjimka Cesty: $_"); $foundExclusion = $true }
            }
            if ($exclusions.ExclusionExtension.Count -gt 0) {
                Add-Finding "Nalezeny následující VÝJIMKY PŘÍPON v Defenderu. Zkontrolujte jejich legitimitu:" $true
                $exclusions.ExclusionExtension | ForEach-Object { Add-Log "  - Přípona: $_"; $Global:uncertainties.Add("Defender Výjimka Přípony: $_"); $foundExclusion = $true }
            }
            if ($exclusions.ExclusionProcess.Count -gt 0) {
                Add-Finding "Nalezeny následující VÝJIMKY PROCESŮ v Defenderu. Zkontrolujte jejich legitimitu:" $true
                $exclusions.ExclusionProcess | ForEach-Object { Add-Log "  - Proces: $_"; $Global:uncertainties.Add("Defender Výjimka Procesu: $_"); $foundExclusion = $true }
            }
            if (-not $foundExclusion) { Add-Log "Nebyly nalezeny žádné nakonfigurované výjimky (cesty, přípony, procesy) v Microsoft Defender." }
        } else { Add-Log "Nepodařilo se získat preference Microsoft Defender (Get-MpPreference selhalo)." -Type "WARNING" }
    } catch { Add-Log "Chyba při kontrole výjimek Defenderu: $($_.Exception.Message)" -Type "ERROR" }


    $actionScan = Confirm-Action "Chcete spustit rychlý sken pomocí Microsoft Defender Antivirus?"
    # ... (kód spuštění Defender skenu z verze 1.1) ...
    if ($actionScan -eq "Yes") {
        Add-Log "Spouštění rychlého skenu Microsoft Defender Antivirus..."
        try {
            Add-Log "Aktualizace definic Microsoft Defender..."
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction SilentlyContinue | Out-Null
            Add-Log "Definice aktualizovány (nebo se aktualizují)."

            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Add-Log "Rychlý sken Microsoft Defender Antivirus dokončen."
            $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue
            if ($detections) {
                Add-Finding "MICROSOFT DEFENDER NALEZL AKTIVNÍ HROZBY!" $true
                $detections | ForEach-Object {
                    $threatMsg = "Defender detekce: $($_.ThreatName), Soubor: $($_.Resources.Path), Stav: $($_.CleaningAction), Akce: $($_.CurrentAction), ID: $($_.ThreatID)"
                    Add-Log $threatMsg -Type "FINDING"
                    $Global:uncertainties.Add($threatMsg)
                }
                Add-Log "Zkontrolujte okamžitě historii detekcí v programu Windows Security a proveďte doporučené akce!" -Type "ERROR"
            } else { Add-Log "Microsoft Defender nenalezl žádné aktuální hrozby při tomto skenu." }
        } catch { # ... ošetření chyby ... 
            Add-Log "Chyba při spouštění/kontrole skenu Microsoft Defender: $($_.Exception.Message)" -Type "ERROR"
            Add-Finding "Nepodařilo se spustit/zkontrolovat sken Microsoft Defender." $true
        }
    } elseif ($actionScan -eq "Skip") { Add-Log "Sken Microsoft Defender přeskočen." }

    Add-Log "--- KONEC SEKCE: Kontrola bezpečnostních nastavení ---" -Type "DEBUG"
}

# --- Funkce pro vytvoření uživatele DOMA (upravená logika) ---
function Ensure-UserDomaExists {
    Add-Log "Kontrola/vytváření uživatelského účtu 'DOMA'..."
    
    $builtInUserSIDsToExclude = @(
        "S-1-5-18", # Local System
        "S-1-5-19", # Local Service
        "S-1-5-20", # Network Service
        "S-1-5-21-*-500", # Administrator (generic pattern for domain or local)
        "S-1-5-21-*-501", # Guest (generic pattern)
        "S-1-5-32-544", # Administrators group SID, not a user but good to be aware
        "S-1-5-32-545"  # Users group SID
    )
    # Přidání dalších známých SIDů nebo jmen vestavěných účtů podle potřeby
    $builtInUserNamesToExclude = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "SYSTEM")

    $allLocalUsers = Get-LocalUser -ErrorAction SilentlyContinue
    $existingStandardUsers = $allLocalUsers | Where-Object {
        $_.Enabled -and 
        ($_.Name -notin $builtInUserNamesToExclude) -and 
        (-not ($builtInUserSIDsToExclude | ForEach-Object { $_.SID.Value -like ($_ -replace '\*' , $PSItem.SID.AccountDomainSid.Value) })) # Porovnání SID patternů
    }

    if ($existingStandardUsers.Count -eq 0) {
        Add-Log "Nebyly nalezeny žádné existující standardní (povolené, ne-vestavěné) lokální uživatelské účty."
        $domaUserExists = $allLocalUsers | Where-Object {$_.Name -eq "DOMA"}
        if ($domaUserExists) {
            Add-Log "Účet 'DOMA' již existuje (ale je jediným standardním účtem nebo jsou ostatní zakázané/vestavěné)."
        } else {
            $createAction = Confirm-Action "Chcete vytvořit lokální uživatelský účet 'DOMA', jelikož neexistují jiné standardní účty?"
            if ($createAction -eq "Yes") {
                Add-Log "Vytváření uživatele 'DOMA'..."
                $Password = $null
                while ($Password -eq $null -or $Password.Length -lt 8) {
                     $PasswordAttempt = Read-Host -Prompt "Zadejte heslo pro nového uživatele 'DOMA' (min. 8 znaků)" -AsSecureString
                     if ($PasswordAttempt.Length -lt 8) { Write-Warning "Heslo je příliš krátké. Musí mít alespoň 8 znaků."}
                     else { $Password = $PasswordAttempt }
                }
                try {
                    New-LocalUser -Name "DOMA" -Password $Password -FullName "Standardní uživatel DOMA" -Description "Standardní uživatelský účet vytvořený skriptem." -PasswordNeverExpires $false -UserMayNotChangePassword $false -ErrorAction Stop
                    Add-LocalGroupMember -Group "Users" -Member "DOMA" -ErrorAction Stop
                    $userToModify = Get-LocalUser -Name "DOMA" -ErrorAction Stop
                    $userToModify.UserMustChangePasswordOnNextLogon = $true
                    $userToModify | Set-LocalUser -ErrorAction Stop
                    Add-Log "Uživatel 'DOMA' úspěšně vytvořen, přidán do skupiny 'Users' a nastaven na změnu hesla při příštím přihlášení."
                    Add-Finding "Byl vytvořen nový lokální uživatel 'DOMA'."
                } catch { # ... ošetření chyby ...
                    Add-Log "Chyba při vytváření uživatele 'DOMA': $($_.Exception.Message)" -Type "ERROR"
                    Add-Finding "Nepodařilo se vytvořit uživatele 'DOMA'." $true
                }
            } elseif ($createAction -eq "Skip") { Add-Log "Vytvoření uživatele 'DOMA' přeskočeno."}
        }
    } else {
        Add-Log "Nalezeny existující standardní (povolené, ne-vestavěné) lokální uživatelské účty. Účet 'DOMA' nebude automaticky vytvořen z tohoto důvodu."
        Add-Log "Existující standardní účty:"
        $existingStandardUsers | ForEach-Object { Add-Log "  - $($_.Name) (SID: $($_.SID.Value))" }
    }
}

# --- Funkce pro nasazení Canary Tokenu ---
function Deploy-CanaryToken {
    Add-Log "Kontrola/Nasazení Canary Tokenu..."
    Write-Host @"
Canary Tokeny jsou návnady (např. soubory nebo odkazy), které vás upozorní,
když k nim někdo přistoupí. Mohou pomoci odhalit neoprávněný přístup k vašim datům.
Tento skript se pokusí vytvořit .XLS soubor (pojmenovaný jako soubor s hesly),
který při otevření odešle upozornění na vámi zadaný email.
"@ -ForegroundColor Cyan

    $action = Confirm-Action "Chcete vytvořit a nasadit .XLS canary token (soubor 'hesla')?"
    if ($action -eq "Yes") {
        $userEmail = ""
        while (-not ($userEmail -match "^\S+@\S+\.\S+$")) { # Základní validace emailu
            $userEmail = Read-Host "Zadejte vaši emailovou adresu pro zasílání upozornění z canary tokenu"
            if (-not ($userEmail -match "^\S+@\S+\.\S+$")) { Write-Warning "Neplatný formát emailové adresy. Zkuste to znovu."}
        }
        
        $encodedEmail = [uri]::EscapeDataString($userEmail)
        $hostnameForMemo = try { (Get-ComputerInfo -ErrorAction SilentlyContinue).CsName } catch { $env:COMPUTERNAME }
        $memo = "Passwords XLS file accessed on $($hostnameForMemo) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $encodedMemo = [uri]::EscapeDataString($memo)

        $tokenBaseUrl = "https://canarytokens.org/generate/msexcel.xls" # Typicky stáhne soubor s názvem msexcel.xls
        $tokenUrl = "$tokenBaseUrl?email=$encodedEmail&memo=$encodedMemo"
        
        $baitFileName = "Důležitá Firemní Hesla $(Get-Random -Minimum 100 -Maximum 999).xls" 
        $baitFilePath = Join-Path -Path $env:USERPROFILE -ChildPath "Documents\$baitFileName" 

        Add-Log "Pokouším se stáhnout canary token (XLS) z canarytokens.org..."
        Add-Log "URL pro generování: $tokenUrl"
        Add-Log "Cílový soubor: $baitFilePath"
        Write-Host "Poznámka: Tato funkce závisí na externí službě canarytokens.org a její aktuální dostupnosti/struktury URL." -ForegroundColor Yellow
        Write-Host "Pokud automatické stažení selže, skript otevře webovou stránku pro manuální vytvoření." -ForegroundColor Yellow

        try {
            Invoke-WebRequest -Uri $tokenUrl -OutFile $baitFilePath -TimeoutSec 60 -ErrorAction Stop
            Add-Log "Canary token XLS soubor '$baitFileName' byl úspěšně stažen a umístěn do '$baitFilePath'."
            Add-Finding "Canary token '$baitFileName' byl nasazen v '$baitFilePath'. Jakékoliv upozornění na email '$userEmail' s poznámkou obsahující '$($hostnameForMemo)' značí potenciální kompromitaci." $true
            Add-Log "DŮLEŽITÉ: Ujistěte se, že jste obdrželi potvrzovací email od canarytokens.org (může být ve spamu). Ověřte funkčnost tokenu jeho bezpečným otevřením (např. v sandboxu nebo na jiném testovacím PC)." -Type "WARNING"
        } catch {
            Add-Log "Chyba při automatickém stahování/nasazení canary tokenu: $($_.Exception.Message)" -Type "ERROR"
            Add-Finding "Nepodařilo se automaticky stáhnout a nasadit canary token. Pokuste se jej vytvořit manuálně." $true
            Add-Log "Otevírám webovou stránku https://canarytokens.org pro manuální vytvoření..."
            try { Start-Process "https://canarytokens.org/generate" -ErrorAction Stop } catch { Add-Log "Nepodařilo se otevřít prohlížeč." -Type "ERROR"}
            Write-Host "Manuální postup: Na webu canarytokens.org zvolte 'MS Excel Document', zadejte email '$userEmail' a popis (memo). Stáhněte soubor a umístěte jej na vhodné místo jako návnadu." -ForegroundColor Yellow
        }
    } elseif ($action -eq "Skip") {
        Add-Log "Vytvoření canary tokenu přeskočeno."
    }
}

# --- Sekce 3: Hardening stanice ---
function Harden-System {
    Add-Log "--- ZAČÁTEK SEKCE: Hardening systému ---" -Type "DEBUG"
    $overallAction = Confirm-Action "Chcete provést základní kroky pro hardening systému?"
    if ($overallAction -eq "No") { Add-Log "Uživatel odmítl hardening systému."; return }
    if ($overallAction -eq "Skip") { Add-Log "Sekce hardeningu byla přeskočena."; return }

    Ensure-UserDomaExists # Upravená logika
    Deploy-CanaryToken    # Nová funkce pro canary token

    # ... (Zbytek hardening kroků: UAC, Firewall, SMBv1, BitLocker, Execution Policy, Auditing CMD a PowerShell - kód z verze 1.1) ...
    # 3.1 Povolení UAC
    try {
        $uacItem = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
        $uacEnabled = if ($uacItem) { $uacItem.EnableLUA } else { -1 } 

        if ($uacEnabled -ne 1) {
            if ($uacEnabled -eq -1) { Add-Log "Registr EnableLUA pro UAC nebyl nalezen." -Type "WARNING" }
            $actionUAC = Confirm-Action "UAC (EnableLUA) je zakázáno nebo není správně nastaveno. Chcete ho povolit? (Vyžaduje restart)"
            if ($actionUAC -eq "Yes") {
                # ... kód pro povolení UAC ...
                Add-Log "Povolování UAC (EnableLUA)..."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWORD -Force
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWORD -Force
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Type DWORD -Force
                Add-Finding "UAC (EnableLUA) bylo povoleno/nastaveno. Pro plnou funkčnost je vyžadován restart."
            } elseif ($actionUAC -eq "Skip") { Add-Log "Povolení UAC přeskočeno." }
        } else { Add-Log "UAC (EnableLUA) je již povoleno."}
    } catch { Add-Log "Nepodařilo se upravit nastavení UAC: $($_.Exception.Message)" -Type "ERROR" }

    # 3.2 Povolení Windows Firewall
    Add-Log "Kontrola stavu Windows Firewall..."
    # ... (kód pro firewall) ...
    $firewallProfiles = Get-NetFirewallProfile -Profile Domain, Private, Public -ErrorAction SilentlyContinue
    $anyDisabled = $firewallProfiles | Where-Object {$_.Enabled -eq $false}
    if ($anyDisabled.Count -gt 0) {
        Add-Log "Některé profily Windows Firewall jsou zakázány:" -Type "WARNING"
        $anyDisabled | ForEach-Object { Add-Log "  - Profil: $($_.Name), Stav: Povoleno=$($_.Enabled)" }
        $actionFirewall = Confirm-Action "Chcete povolit všechny profily Windows Firewall?"
        if ($actionFirewall -eq "Yes") {
            # ... kód pro povolení firewallu ...
            Add-Log "Povolování Windows Firewall pro všechny profily..."
            try {
                Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
                Add-Log "Windows Firewall byl povolen pro všechny profily."
            } catch {
                 Add-Log "Chyba při povolování Windows Firewall: $($_.Exception.Message)" -Type "ERROR"
                 Add-Finding "Nepodařilo se povolit Windows Firewall." $true
            }
        } elseif ($actionFirewall -eq "Skip") { Add-Log "Povolení Windows Firewall přeskočeno." }
    } else { Add-Log "Windows Firewall je povolen pro všechny profily." }

    # 3.3 Kontrola a případné zakázání SMBv1
    Add-Log "Kontrola stavu SMBv1..."
    # ... (kód pro SMBv1) ...
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($smb1Feature -and $smb1Feature.State -eq "Enabled") {
            Add-Finding "SMBv1 je povoleno (jako Windows Feature)! Toto je bezpečnostní riziko. Doporučuje se zakázat." $true
            $actionSMB = Confirm-Action "SMBv1 je povoleno. Chcete ho zakázat? (Může vyžadovat restart)"
            if ($actionSMB -eq "Yes") {
                # ... kód pro zakázání SMBv1 ...
                Add-Log "Zakazování SMBv1 (Windows Feature)..."
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
                Add-Log "Příkaz k zakázání SMBv1 odeslán. Restart může být nutný k dokončení."
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                Add-Finding "SMBv1 bylo zakázáno (nebo byl odeslán příkaz k zakázání). Může být vyžadován restart."
            } elseif ($actionSMB -eq "Skip") { Add-Log "Zakázání SMBv1 přeskočeno." }
        } else { Add-Log "SMBv1 (Windows Feature) je zakázáno nebo nebylo nalezeno." }
    } catch { Add-Log "Chyba při kontrole/konfiguraci SMBv1: $($_.Exception.Message)" -Type "ERROR" }

    # 3.4 Kontrola stavu šifrování BitLocker
    Add-Log "Kontrola stavu šifrování BitLocker pro systémovou jednotku..."
    # ... (kód pro BitLocker) ...
    try {
        $osVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        if ($osVolume) {
            Add-Log "Stav BitLocker pro jednotku OS ($($env:SystemDrive)): $($osVolume.VolumeStatus), Ochrana: $($osVolume.ProtectionStatus)"
            if ($osVolume.VolumeStatus -ne "FullyEncrypted" -or $osVolume.ProtectionStatus -ne "On") {
                Add-Finding "Jednotka OS ($($env:SystemDrive)) není plně šifrována pomocí BitLocker nebo ochrana není zapnuta. Stav: $($osVolume.VolumeStatus), Ochrana: $($osVolume.ProtectionStatus). Doporučuje se povolit a nakonfigurovat šifrování." $true
            }
        } else {
            Add-Log "Nepodařilo se získat informace o BitLocker pro systémovou jednotku (může znamenat, že není povolen nebo podporován)." -Type "WARNING"
            Add-Finding "BitLocker se nezdá být aktivní nebo konfigurován na systémové jednotce. Doporučuje se zvážit šifrování disku." $true
        }
    } catch { Add-Log "Chyba při kontrole stavu BitLocker: $($_.Exception.Message)" -Type "ERROR" }

    # 3.5 PowerShell Execution Policy
    Add-Log "Kontrola PowerShell Execution Policy (LocalMachine)..."
    # ... (kód pro Execution Policy) ...
    $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    Add-Log "Aktuální Execution Policy (LocalMachine): $currentPolicy"
    if ($currentPolicy -notin @("RemoteSigned", "AllSigned", "Restricted")) {
        Add-Finding "PowerShell Execution Policy '$currentPolicy' (LocalMachine) může představovat riziko. Zvažte nastavení na 'RemoteSigned' nebo 'AllSigned'." $true
        $actionExec = Confirm-Action "Chcete nastavit Execution Policy (LocalMachine) na 'RemoteSigned'?"
        if ($actionExec -eq "Yes") {
            # ... kód pro nastavení Execution Policy ...
            Add-Log "Nastavování Execution Policy na 'RemoteSigned'..."
            try {
                Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
                Add-Log "Execution Policy (LocalMachine) byla nastavena na 'RemoteSigned'."
            } catch { Add-Log "Chyba při nastavování Execution Policy: $($_.Exception.Message)" -Type "ERROR" }
        } elseif ($actionExec -eq "Skip") { Add-Log "Změna Execution Policy přeskočena." }
    } else {Add-Log "PowerShell Execution Policy (LocalMachine) je '$currentPolicy', což je považováno za bezpečné nastavení."}

    # 3.6 Auditování CMD (Process Creation)
    $actionAuditCMD = Confirm-Action "Chcete zkontrolovat/povolit auditování vytváření procesů (CMD, atd.)?"
    # ... (kód pro audit CMD) ...
    if ($actionAuditCMD -eq "Yes") {
        Add-Log "Kontrola/Povolování auditování vytváření procesů..."
        try {
            $auditProcessRaw = auditpol /get /subcategory:"Process Creation" /r
            $auditLine = ($auditProcessRaw | Where-Object {$_ -match "Process Creation"})
            $currentProcessAudit = "Neznámé"
            if ($auditLine -match "No Auditing") {$currentProcessAudit = "No Auditing"}
            elseif ($auditLine -match "Success and Failure") {$currentProcessAudit = "Success and Failure"}
            elseif ($auditLine -match "Success") {$currentProcessAudit = "Success"}
            elseif ($auditLine -match "Failure") {$currentProcessAudit = "Failure"}

            Add-Log "Aktuální nastavení auditování 'Process Creation': $currentProcessAudit"
            if ($currentProcessAudit -notmatch "Success and Failure" -and $currentProcessAudit -notmatch "Success") {
                Add-Log "Nastavuji auditování 'Process Creation' na 'Success and Failure'..."
                auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
                Add-Finding "Auditování 'Process Creation' bylo nastaveno/aktualizováno na 'Success and Failure'. Zkontrolujte Security Event Log (ID 4688)."
            } else { Add-Log "Auditování 'Process Creation' je již adekvátně nastaveno ($currentProcessAudit)." }
        } catch { # ... ošetření chyby ...
             Add-Log "Chyba při nastavování auditování 'Process Creation': $($_.Exception.Message)" -Type "ERROR"
            Add-Finding "Chyba při konfiguraci auditování Process Creation." $true
        }
    } elseif ($actionAuditCMD -eq "Skip") { Add-Log "Auditování vytváření procesů přeskočeno."}

    # 3.7 Auditování PowerShell
    $actionPSAudit = Confirm-Action "Chcete zkontrolovat/povolit pokročilé auditování PowerShell (Module Logging, Script Block Logging)?"
    # ... (kód pro audit PowerShell) ...
    if ($actionPSAudit -eq "Yes") {
        Add-Log "Kontrola/Povolování PowerShell Module Logging..."
        $moduleLogKeyPath = "registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $moduleLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

        if (-not (Test-Path $moduleLogKeyPath)) { New-Item -Path $moduleLogKeyPath -Force -ErrorAction SilentlyContinue | Out-Null }
        $moduleLoggingEnabled = (Get-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
        $moduleNames = (Get-ItemProperty -Path $moduleLogPath -Name "ModuleNames" -ErrorAction SilentlyContinue).ModuleNames

        if ($moduleLoggingEnabled -ne 1 -or ($moduleNames -isnot [string[]] -or $moduleNames -notcontains "*" ) -and ($moduleNames -isnot [string] -or $moduleNames -ne "*")) {
            Add-Log "PowerShell Module Logging není plně povoleno pro všechny moduly. Nastavuji..."
            try {
                Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -Type DWORD -Force
                Set-ItemProperty -Path $moduleLogPath -Name "ModuleNames" -Value "*" -Type String -Force 
                Add-Finding "PowerShell Module Logging bylo povoleno pro všechny moduly ('*'). Zkontrolujte PowerShell Operational log (Microsoft-Windows-PowerShell/Operational, ID 4103)."
            } catch { Add-Log "Chyba při nastavování PowerShell Module Logging: $($_.Exception.Message)" -Type "ERROR" }
        } else { Add-Log "PowerShell Module Logging je již povoleno pro všechny moduly." }

        Add-Log "Kontrola/Povolování PowerShell Script Block Logging..."
        $scriptBlockLogKeyPath = "registry::HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $scriptBlockLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

        if (-not (Test-Path $scriptBlockLogKeyPath)) { New-Item -Path $scriptBlockLogKeyPath -Force -ErrorAction SilentlyContinue | Out-Null }
        $scriptBlockLoggingEnabled = (Get-ItemProperty -Path $scriptBlockLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging

        if ($scriptBlockLoggingEnabled -ne 1) {
            Add-Log "PowerShell Script Block Logging není povoleno. Nastavuji..."
            try {
                Set-ItemProperty -Path $scriptBlockLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWORD -Force
                Add-Finding "PowerShell Script Block Logging bylo povoleno. Zkontrolujte PowerShell Operational log (Microsoft-Windows-PowerShell/Operational, ID 4104)."
            } catch { Add-Log "Chyba při nastavování PowerShell Script Block Logging: $($_.Exception.Message)" -Type "ERROR" }
        } else { Add-Log "PowerShell Script Block Logging je již povoleno." }
    } elseif ($actionPSAudit -eq "Skip") { Add-Log "Auditování PowerShell přeskočeno."}

    Add-Log "--- KONEC SEKCE: Hardening systému ---" -Type "DEBUG"
}

# --- Sekce 4: Vyhodnocení a export ---
function Generate-Report {
    # ... (kód beze změny z verze 1.1) ...
    Add-Log "--- ZAČÁTEK SEKCE: Generování reportu ---" -Type "DEBUG"
    $endTime = Get-Date
    $duration = New-TimeSpan -Start $Global:startTime -End $endTime

    Write-Host "`n" + ("=" * 60) -ForegroundColor Green
    Write-Host (" " * 15 + "SHRNUTÍ BEZPEČNOSTNÍ KONTROLY") -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Green
    Write-Host "Čas spuštění skriptu: $($Global:startTime)"
    Write-Host "Čas dokončení skriptu: $endTime"
    Write-Host "Doba trvání: $($duration.ToString())"
    Write-Host ""

    Write-Host "`nNálezy:" -ForegroundColor Yellow
    if ($Global:findings.Count -eq 0) {
        Write-Host "Nebyly nalezeny žádné významné problémy nebo doporučení." -ForegroundColor Green
    } else {
        $Global:findings | ForEach-Object { Write-Host "- $_" -ForegroundColor Yellow }
    }

    if ($Global:uncertainties.Count -gt 0) {
        Write-Host "`n" + ("!" * 60) -ForegroundColor Red
        Write-Host "POZOR: Byly nalezeny nejasnosti vyžadující další expertní analýzu!" -ForegroundColor Red
        Write-Host ("!" * 60) -ForegroundColor Red

        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $ReportFileName = "Security_Analysis_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $ReportFile = Join-Path -Path $DesktopPath -ChildPath $ReportFileName
        $reportContent = @"
Bezpečnostní analýza PowerShell skriptem - $(Get-Date)
=========================================================
Tento soubor obsahuje podrobnosti o potenciálních bezpečnostních problémech,
nebo nejasnostech zjištěných během automatizované kontroly vašeho systému.
Důrazně doporučujeme předat tento soubor odborníkovi na kybernetickou bezpečnost
pro hlubší analýzu a posouzení rizik.

Nalezené nejasnosti a potenciálně závažné nálezy:
-------------------------------------------------
"@
        $Global:uncertainties | ForEach-Object { $reportContent += "`n- $($_ -replace '\r?\n','`r`n  ')`n" } 
        $reportContent += "`n`nCelkový log skriptu (pro kontext):`n" + ("-" * 30) + "`n"
        $Global:logEntries | ForEach-Object { $reportContent += "`n$_" }

        try {
            Set-Content -Path $ReportFile -Value $reportContent -Encoding UTF8 -Force
            Write-Host "`nPodrobnosti o nejasnostech byly exportovány do souboru na vaši plochu:" -ForegroundColor Cyan
            Write-Host $ReportFile -ForegroundColor Cyan
            Write-Host "Prosím, poskytněte tento soubor bezpečnostnímu odborníkovi k revizi." -ForegroundColor Cyan
        } catch {
            Write-Host "`nCHYBA při exportu zprávy do souboru $ReportFile: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Zde jsou nejasnosti (zkopírujte je prosím ručně):" -ForegroundColor Yellow
            $Global:uncertainties | ForEach-Object { Write-Host "- $_" }
        }
    } else {
        Write-Host "`nNebyly nalezeny žádné specifické nejasnosti vyžadující okamžitou externí analýzu dle kritérií skriptu." -ForegroundColor Green
        Write-Host "Přesto doporučujeme pravidelné bezpečnostní kontroly a udržování systému v aktuálním stavu." -ForegroundColor Green
    }
    Write-Host "`n" + ("=" * 60) -ForegroundColor Green
    Add-Log "--- KONEC SEKCE: Generování reportu ---" -Type "DEBUG"
}

# --- Hlavní část skriptu ---
# ... (kód beze změny z verze 1.1, včetně kontroly admin oprávnění, výběru režimu, Start-Transcript, atd.) ...
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "TENTO SKRIPT VYŽADUJE ADMINISTRÁTORSKÁ OPRÁVNĚNÍ! Prosím, spusťte jej jako administrátor."
    Read-Host "Stiskněte Enter pro ukončení."
    exit 1
}

Clear-Host
# ... (uvítací zpráva a výběr režimu) ...
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "    Bezpečnostní skript PowerShell   " -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Vítejte v bezpečnostním skriptu."
Write-Host "Tento skript provede aktualizace, bezpečnostní kontroly (včetně rozšířené detekce)"
Write-Host "a základní hardening vašeho systému (včetně nasazení canary tokenu)."
Write-Host "Před spuštěním se ujistěte, že máte zálohovaná důležitá data." -ForegroundColor Yellow
Write-Host ""

while ($true) {
    Write-Host "Vyberte režim spuštění:"
    Write-Host "1. Interaktivní režim (každý hlavní krok a některé podkroky vyžadují vaše schválení)" -ForegroundColor Green
    Write-Host "2. Autonomní režim (vyžaduje pouze jedno počáteční schválení, poté běží automaticky)" -ForegroundColor Yellow
    Write-Host "Q. Konec (ukončit skript)"
    $choice = Read-Host "Zadejte volbu [1, 2, Q]"
    switch ($choice) {
        '1' { $Global:scriptMode = "Interactive"; Add-Log "Zvolen interaktivní režim."; break }
        '2' { $Global:scriptMode = "Autonomous"; Add-Log "Zvolen autonomní režim."; break }
        'Q' { Add-Log "Uživatel ukončil skript."; exit 0 }
        default { Write-Warning "Neplatná volba. Zkuste to znovu." }
    }
}

if ($Global:scriptMode -eq "Autonomous") {
    Write-Warning "VAROVÁNÍ: Skript bude spuštěn v AUTONOMNÍM REŽIMU."
    Write-Warning "Provede všechny naplánované akce bez dalších dotazů."
    Write-Warning "Ujistěte se, že víte, co děláte."
    $initialConfirm = Read-Host "Chcete pokračovat v autonomním režimu? (Ano/Ne)"
    if ($initialConfirm -notmatch '^(a|ano)$') {
        Add-Log "Autonomní režim nebyl potvrzen. Skript se ukončuje."
        exit 0
    }
    Add-Log "Autonomní režim potvrzen. Skript pokračuje."
}

$TranscriptLogPath = Join-Path -Path $PSScriptRoot -ChildPath "SecurityScriptLog_$(Get-Date -format 'yyyyMMdd_HHmmss').log"
try {
    Start-Transcript -Path $TranscriptLogPath -Append -Force -ErrorAction Stop
    Add-Log "Transkript spuštěn, loguje se do: $TranscriptLogPath"
} catch {
    Add-Log "Nepodařilo se spustit transkript: $($_.Exception.Message)" -Type "ERROR"
    Write-Warning "Nepodařilo se spustit logování do souboru (transkript). Skript bude pokračovat bez něj."
}

Add-Log "Bezpečnostní skript spuštěn v režimu: $($Global:scriptMode)"
Add-Log "Verze PowerShell: $($PSVersionTable.PSVersion)"
Add-Log "Operační systém: $((Get-CimInstance Win32_OperatingSystem).Caption) ($((Get-CimInstance Win32_OperatingSystem).OSArchitecture))"
Add-Log "--- ZAHÁJENÍ HLAVNÍCH OPERACÍ ---" -Type "DEBUG"

try {
    Add-Log "Volání Update-System..." -Type "DEBUG"
    Update-System
    Add-Log "Volání Check-SecuritySettings..." -Type "DEBUG"
    Check-SecuritySettings
    Add-Log "Volání Harden-System..." -Type "DEBUG"
    Harden-System 
    Add-Log "Volání Generate-Report..." -Type "DEBUG"
    Generate-Report
} catch {
    Add-Log "Vyskytla se neočekávaná chyba v hlavní části skriptu: $($_.Exception.ToString())" -Type "CRITICAL_ERROR"
    $Global:uncertainties.Add("KRITICKÁ CHYBA SKRIPTU: $($_.Exception.ToString())")
    Generate-Report 
} finally {
    Add-Log "Bezpečnostní skript dokončil svou činnost (nebo byl přerušen chybou)."
    Write-Host "`nProhlédněte si výstup a případný report na ploše."
    Write-Host "Detailní log všech operací naleznete v souboru: $TranscriptLogPath (pokud byl transkript úspěšně spuštěn)."
    Stop-Transcript -ErrorAction SilentlyContinue
    Read-Host "Stiskněte Enter pro ukončení skriptu."
}
