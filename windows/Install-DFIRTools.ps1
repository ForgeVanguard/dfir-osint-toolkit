<#
.SYNOPSIS
    Install-DFIRTools.ps1 - DFIR toolkit installer for Windows laptops/workstations.

.DESCRIPTION
    Installs a curated set of essential Digital Forensics & Incident Response (DFIR) tools
    plus supporting utilities. Uses winget for most packages (reliable, updatable), and
    targeted downloads + silent install for specialized DFIR suites:
      - Microsoft Sysinternals Suite (full)
      - Eric Zimmerman Tools (MFTECmd, PECmd, LECmd, Registry Explorer, Timeline Explorer, etc.)
      - Autopsy (GUI forensic platform)
      - Volatility 3 (via pip after Python)

    Features:
      * Colored console feedback with [INFO]/[SUCCESS]/[WARN]/[ERROR] status per tool
      * Transcript logging to C:\DFIR\Logs\
      * Creates organized folder structure (Tools, Cases, MemoryDumps, Scripts, etc.)
      * Mostly idempotent (skips or upgrades gracefully where possible)
      * Easy to edit/customize the $Tools array and URLs
      * Post-install hooks (e.g., pip installs)

    REQUIREMENTS
      - Windows 10/11 with winget (built-in on modern systems)
      - Run this script in an elevated PowerShell window (Run as Administrator)
      - Internet connection for downloads
      - Execution policy that allows the script (RemoteSigned recommended)

    USAGE
      1. Review/edit the CONFIGURATION section and $Tools list below.
      2. Open PowerShell as Administrator.
      3. cd to the folder containing this script.
      4. .\Install-DFIRTools.ps1
      5. Review output + transcript log for status.

    CUSTOMIZATION
      - Add/remove tools in the $Tools array.
      - For new winget packages: add Type="Winget", Id="Publisher.Package"
      - For custom MSI/zip: extend the switch logic or add new Type.
      - Update $AutopsyVersion / URL when new Autopsy release drops.
      - Toggle individual installs with comments or add a "Enabled" property.

    CAVEATS
      - Some Sysinternals binaries (PsExec, etc.) and forensic tools are flagged by AV/EDR.
        -> Whitelist C:\DFIR\Tools or specific EXEs after install.
      - Large downloads (Sysinternals ~180MB, Autopsy MSI, EZ Tools collection).
      - winget first-run may require interactive source acceptance (script uses --accept flags).
      - Python PATH refresh may require new PowerShell session after install.
      - Always verify tool hashes/signatures in high-trust environments.
      - This is a starting DFIR workstation build - extend with Velociraptor, KAPE collectors,
        your own scripts, OSQuery, etc. as needed for your workflow.

    NEXT MOVES (recommended after successful run)
      - Open new elevated PS session and verify key commands (procexp64, MFTECmd, autopsy, volatility, etc.).
      - Pin common tools to Start/Taskbar or create desktop shortcuts for GUI ones.
      - Configure VS Code with PowerShell, Python, and Markdown extensions for script/case work.
      - Start populating C:\DFIR\Cases\ and build your first memory/disk image analysis workflow.
      - Consider adding: Velociraptor MSI, OSQuery, BulkExtractor, or your custom IR collection scripts.

.NOTES
    Author : Steven Drew
    License: MIT
    Version: 1.1.0
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$BaseDir = "C:\DFIR",
    [switch]$NoTranscript   # Use -NoTranscript for quick testing / CI-like runs
)

$ErrorActionPreference = "Continue"   # Resilient: continue on single-tool failure
$ProgressPreference = "SilentlyContinue"

#region === CONFIGURATION (EDIT HERE) ===

$BaseToolsDir   = Join-Path $BaseDir "Tools"
$CasesDir       = Join-Path $BaseDir "Cases"
$MemoryDir      = Join-Path $BaseDir "MemoryDumps"
$ScriptsDir     = Join-Path $BaseDir "Scripts"
$LogsDir        = Join-Path $BaseDir "Logs"
$EZToolsDir     = Join-Path $BaseToolsDir "EZTools"

# Autopsy - update version/URL from https://github.com/sleuthkit/autopsy/releases when new release available
$AutopsyVersion = "4.23.1"
$AutopsyMsiUrl  = "https://github.com/sleuthkit/autopsy/releases/download/autopsy-$AutopsyVersion/autopsy-$AutopsyVersion-64bit.msi"

# EZ Tools download (official)
$EZToolsZipUrl  = "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip"

# Curated DFIR + supporting tool list
# Type = Winget | CustomEZ | CustomAutopsy
$Tools = @(
    @{
        Name        = "Git"
        Type        = "Winget"
        Id          = "Git.Git"
        CheckCmd    = "git --version"
        Description = "Version control & scripting foundation"
    },
    @{
        Name        = "Python 3"
        Type        = "Winget"
        Id          = "Python.Python.3.12"
        CheckCmd    = "py -3 --version"
        Description = "Runtime for Volatility 3, custom DFIR scripts, etc."
        PostInstall = {
            Write-Status "Upgrading pip and installing Volatility 3..." "INFO"
            try {
                # PATH is not refreshed in this session after a fresh install; use the py launcher.
                $py = Join-Path $env:SystemRoot 'py.exe'
                if (-not (Test-Path $py)) { $py = 'py' }
                & $py -3 -m pip install --upgrade pip --quiet
                & $py -3 -m pip install volatility3 --quiet
                Write-Status "Volatility 3 installed successfully." "SUCCESS"
            } catch {
                Write-Status "Post-install pip/Volatility step had issues: $_" "WARN"
            }
        }
    },
    @{
        Name        = "Visual Studio Code"
        Type        = "Winget"
        Id          = "Microsoft.VisualStudioCode"
        CheckCmd    = "code --version"
        Description = "Editor for scripts, playbooks, case notes (highly recommended)"
    },
    @{
        Name        = "Wireshark"
        Type        = "Winget"
        Id          = "WiresharkFoundation.Wireshark"
        CheckCmd    = "wireshark --version"
        Description = "Network packet capture & protocol analysis (core DFIR)"
    },
    @{
        Name        = "7-Zip"
        Type        = "Winget"
        Id          = "7zip.7zip"
        CheckCmd    = "7z"
        Description = "Archive handling for evidence containers, memory images, etc."
    },
    @{
        Name        = "Notepad++"
        Type        = "Winget"
        Id          = "Notepad++.Notepad++"
        CheckCmd    = "notepad++ --version"
        Description = "Lightweight text/hex editor (quick artifact review)"
    },
    @{
        Name        = "Sysinternals Suite"
        Type        = "Winget"
        Id          = "Microsoft.Sysinternals.Suite"
        CheckCmd    = "procexp64 /?"
        Description = "Process Explorer, Process Monitor, Autoruns, PsTools, RAMMap, etc. - live response & analysis essentials"
    },
    @{
        Name        = "Eric Zimmerman Tools"
        Type        = "CustomEZ"
        Description = "MFTECmd, PECmd, LECmd, Registry Explorer, Timeline Explorer, SQLECmd, etc. - Windows artifact parsers"
    },
    @{
        Name        = "Autopsy"
        Type        = "CustomAutopsy"
        Description = "Open-source GUI forensic platform (disk images, timelines, modules, carving)"
    }
)

#endregion

#region === HELPER FUNCTIONS ===

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "ERROR"   { "Red" }
        "WARN"    { "Yellow" }
        default   { "Cyan" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-WingetAvailable {
    try {
        $null = winget --version
        return $true
    } catch {
        Write-Status "winget not found or not working. Install App Installer from Microsoft Store or winget-cli release." "ERROR"
        return $false
    }
}

function Install-WingetPackage {
    param(
        [string]$Name,
        [string]$Id
    )
    Write-Status "Checking/installing $Name (winget ID: $Id)..." "INFO"

    # Pre-check
    try {
        $listOutput = winget list --id $Id --exact 2>$null
        if ($listOutput -match [regex]::Escape($Id)) {
            Write-Status "$Name is already installed via winget." "INFO"
            return "AlreadyInstalled"
        }
    } catch {
        Write-Status "winget list failed for $Id; attempting install anyway." "WARN"
    }

    Write-Status "Running winget install for $Name..." "INFO"
    $installArgs = @(
        "install", "--id", $Id,
        "-e",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    # Some packages behave better without forced silent; winget handles it.
    $process = Start-Process -FilePath "winget" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -eq 0) {
        Write-Status "$Name installed/updated successfully." "SUCCESS"
        return "Installed"
    } else {
        Write-Status "$Name install returned exit code $($process.ExitCode). Check winget logs or run manually." "ERROR"
        return "Failed"
    }
}

function Install-EricZimmermanToolSet {
    param([string]$DestDir)

    Write-Status "Preparing Eric Zimmerman Tools collection..." "INFO"
    New-Item -Path $DestDir -ItemType Directory -Force | Out-Null

    $zipPath = Join-Path $env:TEMP "Get-ZimmermanTools_$(Get-Random).zip"
    try {
        Write-Status "Downloading Get-ZimmermanTools.zip..." "INFO"
        Invoke-WebRequest -Uri $EZToolsZipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop

        $extractDir = Join-Path $env:TEMP "EZToolsExtract_$(Get-Random)"
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

        $ps1File = Get-ChildItem -Path $extractDir -Filter "Get-ZimmermanTools.ps1" -Recurse | Select-Object -First 1
        if (-not $ps1File) {
            throw "Get-ZimmermanTools.ps1 not found in downloaded archive."
        }

        Write-Status "Executing Get-ZimmermanTools.ps1 with -Dest $DestDir (this may take several minutes)..." "INFO"
        & $ps1File.FullName -Dest $DestDir

        Write-Status "Eric Zimmerman Tools installed/updated in $DestDir" "SUCCESS"
        return "Installed"
    } catch {
        Write-Status "EZ Tools installation failed: $_" "ERROR"
        return "Failed"
    } finally {
        # Cleanup temp files
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        if ($extractDir) { Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Install-Autopsy {
    param([string]$MsiUrl, [string]$Version)

    Write-Status "Preparing Autopsy $Version installation..." "INFO"
    $msiPath = Join-Path $env:TEMP "autopsy-$Version-64bit.msi"

    try {
        Write-Status "Downloading Autopsy MSI..." "INFO"
        Invoke-WebRequest -Uri $MsiUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop

        Write-Status "Running silent MSI install (this can take 5-10+ minutes)..." "INFO"
        $logPath = Join-Path $LogsDir "Autopsy_Install_$(Get-Date -Format yyyyMMdd_HHmmss).log"

        $msiArgs = @(
            "/i", "`"$msiPath`"",
            "/qn",
            "/norestart",
            "/l*v", "`"$logPath`""
        )

        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {  # 3010 = reboot required, rare for this
            Write-Status "Autopsy $Version installed successfully. (Install log: $logPath)" "SUCCESS"
            return "Installed"
        } else {
            Write-Status "Autopsy MSI returned exit code $($process.ExitCode). See log: $logPath" "ERROR"
            return "Failed"
        }
    } catch {
        Write-Status "Autopsy installation failed: $_" "ERROR"
        return "Failed"
    } finally {
        Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region === MAIN EXECUTION ===

Write-Host ""
Write-Host "+============================================================================+" -ForegroundColor Cyan
Write-Host "|              DFIR TOOLKIT INSTALLER - Windows Laptop / Workstation         |" -ForegroundColor Cyan
Write-Host "+============================================================================+" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-WingetAvailable)) {
    Write-Status "Cannot continue without winget. Exiting." "ERROR"
    exit 1
}

# Create folder structure
Write-Status "Creating DFIR folder structure under $BaseDir..." "INFO"
@($BaseDir, $BaseToolsDir, $CasesDir, $MemoryDir, $ScriptsDir, $LogsDir, $EZToolsDir) | ForEach-Object {
    New-Item -Path $_ -ItemType Directory -Force | Out-Null
}

# Start logging
$transcriptPath = $null
if (-not $NoTranscript) {
    $transcriptPath = Join-Path $LogsDir "Install-DFIRTools_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    try {
        Start-Transcript -Path $transcriptPath -Append -ErrorAction Stop | Out-Null
        Write-Status "Transcript logging to: $transcriptPath" "INFO"
    } catch {
        Write-Status "Could not start transcript: $_" "WARN"
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$startTime = Get-Date

foreach ($tool in $Tools) {
    Write-Host ""
    Write-Host "----------------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Status "Processing: $($tool.Name) - $($tool.Description)" "INFO"

    $resultStatus = "Pending"

    try {
        switch ($tool.Type) {
            "Winget" {
                $resultStatus = Install-WingetPackage -Name $tool.Name -Id $tool.Id
                if ($resultStatus -eq "Installed" -and $tool.PostInstall) {
                    & $tool.PostInstall
                }
            }
            "CustomEZ" {
                $resultStatus = Install-EricZimmermanToolSet -DestDir $EZToolsDir
            }
            "CustomAutopsy" {
                $resultStatus = Install-Autopsy -MsiUrl $AutopsyMsiUrl -Version $AutopsyVersion
            }
            default {
                Write-Status "Unknown tool type '$($tool.Type)' for $($tool.Name)" "ERROR"
                $resultStatus = "Failed"
            }
        }
    } catch {
        Write-Status "Unexpected error processing $($tool.Name): $_" "ERROR"
        $resultStatus = "Failed"
    }

    $results.Add([pscustomobject]@{
        Tool        = $tool.Name
        Type        = $tool.Type
        Status      = $resultStatus
        Timestamp   = Get-Date
    })
}

#endregion

#region === SUMMARY & CLEANUP ===

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "                           INSTALLATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

$grouped = $results | Group-Object -Property Status | Sort-Object Name
foreach ($g in $grouped) {
    $count = $g.Count
    $color = switch ($g.Name) {
        "Installed"        { "Green" }
        "AlreadyInstalled" { "Cyan" }
        "Failed"           { "Red" }
        default            { "Yellow" }
    }
    Write-Host ("  {0,-18} : {1}" -f $g.Name, $count) -ForegroundColor $color
}

Write-Host ""
Write-Host "Detailed results:" -ForegroundColor Gray
$results | Format-Table -Property Tool, Status, Timestamp -AutoSize | Out-Host

$duration = (Get-Date) - $startTime
Write-Host ""
Write-Status "Total runtime: $($duration.ToString('mm\:ss'))" "INFO"
Write-Status "Tools location: $BaseToolsDir" "INFO"
Write-Status "EZ Tools:       $EZToolsDir" "INFO"
Write-Status "Cases / Memory: $CasesDir / $MemoryDir" "INFO"
if ($transcriptPath) {
    Write-Status "Full log:       $transcriptPath" "INFO"
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open a NEW PowerShell window (to refresh PATH for Python/winget tools)." -ForegroundColor Yellow
Write-Host "  2. Test key commands: procexp64, MFTECmd, autopsy, vol -h  (or: py -3 -m volatility3)" -ForegroundColor Yellow
Write-Host "  3. Whitelist C:\DFIR in your AV/EDR if tools are blocked." -ForegroundColor Yellow
Write-Host "  4. Extend the `$Tools list as needed (Velociraptor, KAPE, OSQuery, etc.)." -ForegroundColor Yellow
Write-Host ""

if (-not $NoTranscript -and $transcriptPath) {
    Stop-Transcript | Out-Null
}

Write-Host "Script complete." -ForegroundColor Cyan
Write-Host ""

#endregion
