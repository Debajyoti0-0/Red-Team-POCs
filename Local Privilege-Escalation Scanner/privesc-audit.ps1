#Requires -Version 5.1
[CmdletBinding()]
param(
    [Alias("h")]
    [switch]$Help,

    [Alias("o")]
    [string]$OutputPath = (Get-Location).Path,

    [Alias("f")]
    [ValidateSet("Table", "CSV", "HTML", "All")]
    [string]$Format = "Table",

    [switch]$IncludeServices = $true,
    [switch]$IncludeScheduledTasks = $true,

    [Alias("e")]
    [switch]$AutoElevate,

    [string]$LogFile,

    [Alias("m")]
    [ValidateSet("All", "Medium", "High", "Critical")]
    [string]$MinSeverity = "All",

    [Alias("x")]
    [ValidateSet("DLL", "Service", "ScheduledTask")]
    [string[]]$ExcludeCategory = @(),

    [switch]$NoColor,

    [Alias("q")]
    [switch]$Quiet,

    [switch]$Version,

    # Catches things like "--help" that PowerShell's single-dash parser
    # won't bind to a named parameter, so we can still detect them.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Remaining
)

$ScriptVersion = "1.1.0"

function Show-Help {
    $help = @"

PRIVESC-AUDIT.PS1  (v$ScriptVersion)
Local privilege-escalation surface scanner - writable DLLs/directories on
NT AUTHORITY processes, weak service binary/registry ACLs, and SYSTEM-run
scheduled tasks with writable action executables. Read-only, makes no changes.

USAGE
    .\privesc-audit.ps1 [-h|--help] [options]

OPTIONS
    -h, --help, -Help           Show this help and exit.
    -Version                    Show script version and exit.

    -o, -OutputPath <path>      Directory for CSV/HTML/log output. Default: current directory.
    -f, -Format <fmt>           Table | CSV | HTML | All. Default: Table.

    -IncludeServices[:`$false]   Audit service binaries + registry key ACLs. Default: on.
    -IncludeScheduledTasks[:`$false]
                                 Audit SYSTEM-run scheduled tasks. Default: on.
    -x, -ExcludeCategory <c>    Skip a category entirely: DLL, Service, ScheduledTask.
                                 Repeatable, e.g. -ExcludeCategory DLL,ScheduledTask

    -m, -MinSeverity <level>    Only show findings at or above this severity:
                                 All (default) | Medium | High | Critical

    -e, -AutoElevate            If not running elevated, relaunch elevated automatically.
    -LogFile <path>             Debug log path. Default: <OutputPath>\privesc-audit.log
    -NoColor                    Disable colorized console output (e.g. for redirecting to a file).
    -q, -Quiet                  Suppress INFO/DEBUG log lines; only WARN/ERROR and results show.
    -Verbose                    Show DEBUG-level log lines (built-in PowerShell common parameter).

EXAMPLES
    .\privesc-audit.ps1 -AutoElevate -Format HTML
    .\privesc-audit.ps1 -IncludeServices:`$false -Format CSV -OutputPath C:\Audit
    .\privesc-audit.ps1 -MinSeverity High -ExcludeCategory ScheduledTask
    .\privesc-audit.ps1 --help

"@
    Write-Host $help
}

if ($Version) {
    Write-Host "privesc-audit.ps1 v$ScriptVersion"
    return
}

if ($Help -or ($Remaining | Where-Object { $_ -in @("--help", "-help", "/?", "/help") })) {
    Show-Help
    return
}

if ($Remaining -and $Remaining.Count -gt 0) {
    Write-Host "Unrecognized argument(s): $($Remaining -join ', ')" -ForegroundColor Yellow
    Write-Host "Run with -h or --help to see available options." -ForegroundColor Yellow
    return
}

# =============================================================================
# LOGGING / AUTO-DEBUG INFRASTRUCTURE
# =============================================================================

if (-not $LogFile) { $LogFile = Join-Path $OutputPath "privesc-audit.log" }

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")][string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"

    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "DEBUG" { "DarkGray" }
        default { "Gray" }
    }

    $shouldPrint = switch ($Level) {
        "DEBUG"  { $VerbosePreference -eq "Continue" }
        "INFO"   { -not $Quiet }
        default  { $true }  # WARN / ERROR always print
    }
    if ($shouldPrint) {
        if ($NoColor) { Write-Host $line } else { Write-Host $line -ForegroundColor $color }
    }
    try { Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop } catch { }
}

function Invoke-WithRetry {
    <#
        Wraps a scriptblock with retry logic for transient failures
        (file locks, WMI timeouts, etc). Logs full exception detail on
        each attempt instead of failing silently. Returns $null after
        exhausting retries so callers can branch on failure explicitly.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Context = "operation",
        [int]$MaxAttempts = 3,
        [int]$DelayMs = 250
    )
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Action
        }
        catch {
            $ex = $_.Exception
            Write-Log -Level DEBUG -Message "Attempt $attempt/$MaxAttempts failed for '$Context': $($ex.GetType().Name) - $($ex.Message)"
            if ($attempt -eq $MaxAttempts) {
                Write-Log -Level WARN -Message "Giving up on '$Context' after $MaxAttempts attempts. Last error: $($ex.Message)"
                return $null
            }
            Start-Sleep -Milliseconds $DelayMs
        }
    }
}

function Test-Prerequisites {
    <#
        Checks everything that would otherwise cause silent empty results,
        and reports exactly which one failed instead of just returning nothing.
    #>
    $issues = @()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $issues += "Not running elevated - SYSTEM process/service/module enumeration will fail or return partial data."
    }

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell $($PSVersionTable.PSVersion) detected - some cmdlets (Get-CimInstance, ScheduledTasks module) require 5.1+."
    }

    if ($IncludeScheduledTasks -and -not (Get-Module -ListAvailable -Name ScheduledTasks)) {
        $issues += "ScheduledTasks module not available - scheduled task audit will be skipped."
    }

    if (-not (Test-Path $OutputPath)) {
        try { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
        catch { $issues += "OutputPath '$OutputPath' does not exist and could not be created: $($_.Exception.Message)" }
    }

    return @{ IsAdmin = $isAdmin; Issues = $issues }
}

# =============================================================================
# SELF-ELEVATION
# =============================================================================

$prereq = Test-Prerequisites
if (-not $prereq.IsAdmin) {
    if ($AutoElevate) {
        Write-Log -Level WARN -Message "Not elevated. Relaunching with AutoElevate..."
        $scriptPath = $MyInvocation.MyCommand.Path
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"",
                     "-OutputPath", "`"$OutputPath`"", "-Format", $Format)
        if ($IncludeServices)        { $argList += "-IncludeServices" }
        if ($IncludeScheduledTasks)  { $argList += "-IncludeScheduledTasks" }
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argList -Verb RunAs -ErrorAction Stop
        }
        catch {
            Write-Log -Level ERROR -Message "Elevation was declined or failed: $($_.Exception.Message)"
        }
        return
    }
    else {
        foreach ($i in $prereq.Issues) { Write-Log -Level WARN -Message $i }
        Write-Log -Level WARN -Message "Continuing without elevation. Results will be incomplete. Re-run with -AutoElevate to fix this automatically."
    }
}
foreach ($i in $prereq.Issues) {
    if ($i -notmatch "elevated") { Write-Log -Level WARN -Message $i }
}

Write-Log -Level INFO -Message "Starting privesc audit. Elevated=$($prereq.IsAdmin) Format=$Format Services=$IncludeServices ScheduledTasks=$IncludeScheduledTasks"

# =============================================================================
# SHARED ACL EVALUATION
# =============================================================================

# Broader than "just NT AUTHORITY / owner / Administrators" - these are the
# groups that actually show up in real-world writable-by-non-privileged-user findings.
$WeakIdentityPatterns = @(
    "Everyone",
    "*Authenticated Users*",
    "BUILTIN\Users",
    "NT AUTHORITY\INTERACTIVE",
    "NT AUTHORITY\*"
)

function Get-WeakRights {
    param([Parameter(Mandatory)]$AclEntries, [string]$OwningAccount)

    $findings = @()
    foreach ($entry in $AclEntries) {
        if ($entry.AccessControlType -ne "Allow") { continue }

        $idRef = $entry.IdentityReference.ToString()
        $isWeakIdentity = $false
        foreach ($pattern in $WeakIdentityPatterns) {
            if ($idRef -like $pattern) { $isWeakIdentity = $true; break }
        }
        if ($idRef -eq $OwningAccount -or $idRef -eq "BUILTIN\Administrators") {
            $isWeakIdentity = $true
        }
        if (-not $isWeakIdentity) { continue }

        $rights = $entry.FileSystemRights.ToString()
        if ($rights -notmatch "Write|Modify|FullControl") { continue }

        # Severity: broad low-priv identity + strong rights = worse
        $severity = "Medium"
        if ($idRef -eq "Everyone" -or $idRef -like "*Authenticated Users*" -or $idRef -eq "BUILTIN\Users") {
            $severity = if ($rights -match "FullControl|Modify") { "Critical" } else { "High" }
        }

        $findings += [PSCustomObject]@{
            Identity  = $idRef
            Rights    = $rights
            Severity  = $severity
        }
    }
    return $findings
}

function Get-DirectoryWriteRisk {
    <#
        A locked-down DLL sitting in a writable directory is still exploitable -
        an attacker deletes/renames won't work without file rights, but many
        search-order hijacks just need to PLANT a new DLL, which only needs
        directory Write/CreateFiles, not rights on the target file itself.
    #>
    param([string]$Path, [string]$OwningAccount)

    $dir = Split-Path -Parent $Path
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { return @() }

    $acl = Invoke-WithRetry -Context "Get-Acl($dir)" -Action { Get-Acl -LiteralPath $dir -ErrorAction Stop }
    if (-not $acl) { return @() }

    return Get-WeakRights -AclEntries $acl.Access -OwningAccount $OwningAccount
}

# =============================================================================
# CHECK 1: PROCESS MODULE (DLL) HIJACK SURFACE
# =============================================================================

function Invoke-DllHijackAudit {
    Write-Log -Level INFO -Message "Auditing loaded modules of NT AUTHORITY processes..."
    $findings = @()
    $skippedNoOwner = 0
    $skippedNotNtAuthority = 0
    $processed = 0

    $procs = Invoke-WithRetry -Context "Get-CimInstance Win32_Process" -Action { Get-CimInstance Win32_Process -ErrorAction Stop }
    if (-not $procs) {
        Write-Log -Level ERROR -Message "Could not enumerate processes at all. Aborting DLL audit."
        return $findings
    }

    foreach ($p in $procs) {
        $owner = Invoke-WithRetry -MaxAttempts 1 -Context "GetOwner PID $($p.ProcessId)" -Action {
            Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        }
        if (-not $owner -or $owner.ReturnValue -ne 0) { $skippedNoOwner++; continue }
        if ($owner.Domain -ne "NT AUTHORITY") { $skippedNotNtAuthority++; continue }

        $processed++
        $account = "$($owner.Domain)\$($owner.User)"

        $modules = Invoke-WithRetry -MaxAttempts 1 -Context "Get-Process -Module PID $($p.ProcessId)" -Action {
            Get-Process -Id $p.ProcessId -Module -ErrorAction Stop
        }
        if (-not $modules) {
            $findings += [PSCustomObject]@{
                Category = "DLL"; PID = $p.ProcessId; Process = $p.Name; Account = $account
                Target = "-"; Severity = "-"; Detail = "-"; Status = "ACCESS DENIED"
            }
            continue
        }

        foreach ($module in $modules) {
            $dllPath = $module.FileName
            if (-not $dllPath -or -not (Test-Path -LiteralPath $dllPath -PathType Leaf)) { continue }

            $acl = Invoke-WithRetry -MaxAttempts 1 -Context "Get-Acl($dllPath)" -Action { Get-Acl -LiteralPath $dllPath -ErrorAction Stop }
            $fileFindings = if ($acl) { Get-WeakRights -AclEntries $acl.Access -OwningAccount $account } else { @() }
            $dirFindings  = Get-DirectoryWriteRisk -Path $dllPath -OwningAccount $account

            foreach ($f in $fileFindings) {
                $findings += [PSCustomObject]@{
                    Category = "DLL (file writable)"; PID = $p.ProcessId; Process = $p.Name; Account = $account
                    Target = $dllPath; Severity = $f.Severity; Detail = "$($f.Identity): $($f.Rights)"; Status = "OK"
                }
            }
            foreach ($f in $dirFindings) {
                $findings += [PSCustomObject]@{
                    Category = "DLL (dir plantable)"; PID = $p.ProcessId; Process = $p.Name; Account = $account
                    Target = (Split-Path -Parent $dllPath); Severity = $f.Severity; Detail = "$($f.Identity): $($f.Rights)"; Status = "OK"
                }
            }
        }
    }

    Write-Log -Level INFO -Message "DLL audit: processed=$processed skipped(no owner)=$skippedNoOwner skipped(not NT AUTHORITY)=$skippedNotNtAuthority findings=$($findings.Count)"
    return $findings
}

# =============================================================================
# CHECK 2: SERVICE BINARY + REGISTRY KEY WEAKNESS
# =============================================================================

function Invoke-ServiceAudit {
    Write-Log -Level INFO -Message "Auditing Windows service binaries and registry keys..."
    $findings = @()

    $services = Invoke-WithRetry -Context "Get-CimInstance Win32_Service" -Action { Get-CimInstance Win32_Service -ErrorAction Stop }
    if (-not $services) {
        Write-Log -Level ERROR -Message "Could not enumerate services. Skipping service audit."
        return $findings
    }

    foreach ($svc in $services) {
        $pathName = $svc.PathName
        if (-not $pathName) { continue }

        # --- Unquoted service path check (classic privesc if path has spaces) ---
        if ($pathName -notmatch '^"' -and $pathName -match '\.exe' -and $pathName -match ' ') {
            $exeGuess = $pathName -replace '\.exe.*$', '.exe'
            if ($exeGuess -match ' ') {
                $findings += [PSCustomObject]@{
                    Category = "Service (unquoted path)"; PID = "-"; Process = $svc.Name; Account = $svc.StartName
                    Target = $pathName; Severity = "High"; Detail = "Unquoted path with spaces allows binary planting in an intermediate segment"; Status = "OK"
                }
            }
        }

        # --- Binary file ACL ---
        $exePath = ($pathName -replace '^"([^"]+)".*$', '$1') -replace '^([^ ]+\.exe).*$', '$1'
        if (Test-Path -LiteralPath $exePath -PathType Leaf) {
            $acl = Invoke-WithRetry -MaxAttempts 1 -Context "Get-Acl($exePath)" -Action { Get-Acl -LiteralPath $exePath -ErrorAction Stop }
            if ($acl) {
                foreach ($f in (Get-WeakRights -AclEntries $acl.Access -OwningAccount $svc.StartName)) {
                    $findings += [PSCustomObject]@{
                        Category = "Service (binary writable)"; PID = "-"; Process = $svc.Name; Account = $svc.StartName
                        Target = $exePath; Severity = $f.Severity; Detail = "$($f.Identity): $($f.Rights)"; Status = "OK"
                    }
                }
            }
        }

        # --- Registry key ACL: HKLM\SYSTEM\CurrentControlSet\Services\<name> ---
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        $regAcl = Invoke-WithRetry -MaxAttempts 1 -Context "Get-Acl($regPath)" -Action { Get-Acl -LiteralPath $regPath -ErrorAction Stop }
        if ($regAcl) {
            foreach ($entry in $regAcl.Access) {
                if ($entry.AccessControlType -ne "Allow") { continue }
                $idRef = $entry.IdentityReference.ToString()
                $isWeak = ($idRef -eq "Everyone" -or $idRef -like "*Authenticated Users*" -or $idRef -eq "BUILTIN\Users")
                if (-not $isWeak) { continue }
                $rights = $entry.RegistryRights.ToString()
                if ($rights -notmatch "SetValue|FullControl|WriteKey|CreateSubKey") { continue }
                $findings += [PSCustomObject]@{
                    Category = "Service (registry key writable)"; PID = "-"; Process = $svc.Name; Account = $svc.StartName
                    Target = $regPath; Severity = "Critical"; Detail = "$($idRef): $rights (ImagePath hijack possible)"; Status = "OK"
                }
            }
        }
    }

    Write-Log -Level INFO -Message "Service audit: findings=$($findings.Count)"
    return $findings
}

# =============================================================================
# CHECK 3: SCHEDULED TASKS RUNNING AS SYSTEM WITH WEAK ACTION PERMISSIONS
# =============================================================================

function Invoke-ScheduledTaskAudit {
    Write-Log -Level INFO -Message "Auditing scheduled tasks..."
    $findings = @()

    if (-not (Get-Module -ListAvailable -Name ScheduledTasks)) {
        Write-Log -Level WARN -Message "ScheduledTasks module unavailable, skipping."
        return $findings
    }

    $tasks = Invoke-WithRetry -Context "Get-ScheduledTask" -Action { Get-ScheduledTask -ErrorAction Stop }
    if (-not $tasks) { return $findings }

    foreach ($task in $tasks) {
        $principal = $task.Principal
        if ($principal.UserId -notmatch "SYSTEM|LOCAL SERVICE|NETWORK SERVICE|NT AUTHORITY") { continue }

        foreach ($action in $task.Actions) {
            $exe = $action.Execute
            if (-not $exe) { continue }
            $exe = $exe.Trim('"')
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }

            $acl = Invoke-WithRetry -MaxAttempts 1 -Context "Get-Acl($exe)" -Action { Get-Acl -LiteralPath $exe -ErrorAction Stop }
            if (-not $acl) { continue }
            foreach ($f in (Get-WeakRights -AclEntries $acl.Access -OwningAccount $principal.UserId)) {
                $findings += [PSCustomObject]@{
                    Category = "ScheduledTask (action writable)"; PID = "-"; Process = $task.TaskName; Account = $principal.UserId
                    Target = $exe; Severity = $f.Severity; Detail = "$($f.Identity): $($f.Rights)"; Status = "OK"
                }
            }
        }
    }

    Write-Log -Level INFO -Message "Scheduled task audit: findings=$($findings.Count)"
    return $findings
}

# =============================================================================
# RUN
# =============================================================================

$allFindings = @()
$allFindings += Invoke-DllHijackAudit
if ($IncludeServices) { $allFindings += Invoke-ServiceAudit }
if ($IncludeScheduledTasks) { $allFindings += Invoke-ScheduledTaskAudit }

$severityOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "-" = 3 }

# -ExcludeCategory takes short names (DLL/Service/ScheduledTask); Category
# values on findings are more specific (e.g. "DLL (dir plantable)"), so match by prefix.
if ($ExcludeCategory -and $ExcludeCategory.Count -gt 0) {
    $allFindings = $allFindings | Where-Object {
        $cat = $_.Category
        -not ($ExcludeCategory | Where-Object { $cat -like "$_*" })
    }
}

if ($MinSeverity -ne "All") {
    $threshold = $severityOrder[$MinSeverity]
    $allFindings = $allFindings | Where-Object { $_.Severity -eq "-" -or $severityOrder[$_.Severity] -le $threshold }
}

$allFindings = $allFindings | Sort-Object { $severityOrder[$_.Severity] }, Category

function Write-ColorTable {
    <#
        Format-Table can't color individual rows, so this builds an aligned
        table manually and Write-Host's each row in a color keyed to Severity.
        Columns: Category, Process, Account, Target, Severity, Detail
    #>
    param([Parameter(Mandatory)][array]$Rows)

    if (-not $Rows -or $Rows.Count -eq 0) { return }

    $cols = @(
        @{ Name = "Category"; Prop = "Category" }
        @{ Name = "Process";  Prop = "Process" }
        @{ Name = "Account";  Prop = "Account" }
        @{ Name = "Target";   Prop = "Target" }
        @{ Name = "Severity"; Prop = "Severity" }
        @{ Name = "Detail";   Prop = "Detail" }
    )

    # Cap Target/Detail width so long paths don't blow out the console
    $maxTarget = 60
    $maxDetail = 50

    foreach ($r in $Rows) {
        if ($r.Target -and $r.Target.Length -gt $maxTarget) { $r.Target = "..." + $r.Target.Substring($r.Target.Length - ($maxTarget - 3)) }
        if ($r.Detail -and $r.Detail.Length -gt $maxDetail) { $r.Detail = $r.Detail.Substring(0, $maxDetail - 3) + "..." }
    }

    $widths = @{}
    foreach ($c in $cols) {
        $dataMax = ($Rows | ForEach-Object { "$($_.($c.Prop))".Length } | Measure-Object -Maximum).Maximum
        $widths[$c.Name] = [Math]::Max($c.Name.Length, [int]$dataMax)
    }

    # Header
    $headerLine = ($cols | ForEach-Object { $_.Name.PadRight($widths[$_.Name]) }) -join "  "
    if ($NoColor) { Write-Host $headerLine } else { Write-Host $headerLine -ForegroundColor Cyan }
    if ($NoColor) { Write-Host ("-" * $headerLine.Length) } else { Write-Host ("-" * $headerLine.Length) -ForegroundColor DarkGray }

    foreach ($r in $Rows) {
        $color = switch ($r.Severity) {
            "Critical" { "Red" }
            "High"     { "Yellow" }
            "Medium"   { "Cyan" }
            default    { if ($r.Status -eq "ACCESS DENIED") { "DarkGray" } else { "Gray" } }
        }
        $line = ($cols | ForEach-Object { "$($r.($_.Prop))".PadRight($widths[$_.Name]) }) -join "  "
        if ($NoColor) { Write-Host $line } else { Write-Host $line -ForegroundColor $color }
    }

    if (-not $NoColor) {
        Write-Host ""
        Write-Host "Legend: " -NoNewline -ForegroundColor DarkGray
        Write-Host "Critical " -NoNewline -ForegroundColor Red
        Write-Host "High " -NoNewline -ForegroundColor Yellow
        Write-Host "Medium " -NoNewline -ForegroundColor Cyan
        Write-Host "Info/Denied" -ForegroundColor DarkGray
    }
}

# =============================================================================
# OUTPUT
# =============================================================================

if (-not $Quiet) {
    Write-Host ""
    if ($NoColor) { Write-Host "=== SUMMARY ===" } else { Write-Host "=== SUMMARY ===" -ForegroundColor Cyan }
    $allFindings | Where-Object Severity -ne "-" | Group-Object Severity | Sort-Object { $severityOrder[$_.Name] } | ForEach-Object {
        $c = switch ($_.Name) { "Critical" {"Red"} "High" {"Yellow"} "Medium" {"White"} default {"Gray"} }
        if ($NoColor) { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) }
        else { Write-Host ("  {0,-10} {1}" -f $_.Name, $_.Count) -ForegroundColor $c }
    }
    Write-Host ""
}

if (-not $allFindings -or $allFindings.Count -eq 0) {
    Write-Log -Level WARN -Message "No findings at all. If not elevated, re-run with -AutoElevate. Check $LogFile for skip/processed counters."
}
else {
    if ($Format -in @("Table", "All")) {
        Write-ColorTable -Rows $allFindings
    }
    if ($Format -in @("CSV", "All")) {
        $csvPath = Join-Path $OutputPath "privesc-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $allFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log -Level INFO -Message "CSV written: $csvPath"
    }
    if ($Format -in @("HTML", "All")) {
        $htmlPath = Join-Path $OutputPath "privesc-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $rows = $allFindings | ForEach-Object {
            $sevColor = switch ($_.Severity) { "Critical" {"#ffcccc"} "High" {"#fff2cc"} "Medium" {"#e6f2ff"} default {"#f2f2f2"} }
            "<tr style='background:$sevColor'><td>$($_.Category)</td><td>$($_.Process)</td><td>$($_.Account)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Target))</td><td>$($_.Severity)</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td></tr>"
        }
        $html = @"
<html><head><title>PrivEsc Audit Report</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:13px} table{border-collapse:collapse;width:100%} td,th{border:1px solid #ccc;padding:6px;text-align:left} th{background:#333;color:#fff}</style>
</head><body>
<h2>Local Privilege Escalation Surface Audit</h2>
<p>Generated: $(Get-Date)</p>
<table><tr><th>Category</th><th>Process/Task/Service</th><th>Account</th><th>Target</th><th>Severity</th><th>Detail</th></tr>
$($rows -join "`n")
</table></body></html>
"@
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Log -Level INFO -Message "HTML report written: $htmlPath"
    }
}

Write-Log -Level INFO -Message "Audit complete. Total findings: $($allFindings.Count). Log: $LogFile"
