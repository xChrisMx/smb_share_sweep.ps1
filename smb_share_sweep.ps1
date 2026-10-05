<#
.SYNOPSIS
    Large-scale SMB share discovery across many subnets, running as the
    current user (no credentials needed -- same model as Snaffler).

.DESCRIPTION
    Pipeline:
      1. Phase 1: TCP/445 sweep of every subnet using batched async connects
         inside a runspace pool (PS 5.1 has no ForEach-Object -Parallel).
      2. Phase 2: NetShareEnum (Win32 API, P/Invoke) against every live host,
         using the CURRENT logon token -- no -Credential needed, same as
         Snaffler. Each disk share's read access is tested with Get-ChildItem.
         Reverse DNS (bounded, async, real timeout) fills in a best-effort
         hostname per host.
      3. Results written to one .xlsx (ImportExcel module): Overview /
         Results / Hosts / Detailed Stats, plus a companion .csv (same rows
         as Results). Write-Progress bars on both phases.

    USE ONLY ON NETWORKS / HOSTS YOU ARE AUTHORIZED TO ASSESS.

    SAFETY NOTES
      - Read-only. No write/delete is ever attempted against a remote share
        (an earlier revision had a write-probe; it was removed -- this tool
        only confirms a share is readable).
      - No credentials are collected, stored, or transmitted by this script.
        It rides whatever access your current logon session already has.
      - -MaxAddressesWithoutForce defaults to 20,000,000 -- comfortably above
        the full built-in $DefaultSubnets list (~18.15M addresses), so the
        default scope runs without -Force. It still refuses anything bigger
        than that (e.g. an accidental extra /8 tacked onto -Subnets) unless
        you pass -Force, so a genuine typo can't silently start a run far
        larger than your actual environment.
      - KNOWN LIMITATION: a single slow/hung share (e.g. a dead DFS target)
        cannot be forcibly cancelled mid-read from pure PowerShell -- a
        blocked Win32 file-I/O call doesn't respond to cooperative
        cancellation (tested: PowerShell's own pipeline .Stop() just waits
        out the same OS-level timeout anyway, ~20s+, instead of actually
        cutting it short). Impact is bounded, not eliminated: hosts are
        processed in small batches per runspace-pool thread, so a hang only
        delays the handful of hosts in that one batch, not the whole sweep.

    NOTE ON SCALE: this does TCP handshakes, not raw SYN packets -- it will
    be far slower than masscan on huge ranges (10.0.0.0/8 = ~16.7M addresses).
    Test on a /24 first and tune -Threads/-BatchSize/-PortTimeoutMs before
    pointing this at anything bigger than a /16.

.PARAMETER Subnets
    Override the built-in $Subnets list for this run.

.PARAMETER Threads
    Concurrent runspaces for the port-445 sweep (each handles one batch).

.PARAMETER BatchSize
    IPs per batch in the port sweep. Total simultaneous sockets in flight is
    roughly Threads * BatchSize -- keep that comfortably under a few thousand
    to avoid exhausting ephemeral ports.

.PARAMETER PortTimeoutMs
    How long to wait for the whole batch's connects to resolve. LAN: 500-1000ms.
    WAN/slow links: raise it.

.PARAMETER ShareThreads
    Concurrent runspaces for the SMB share-enumeration phase.

.PARAMETER HostnameTimeoutMs
    Per-host reverse-DNS timeout (true async cancellation, not best-effort --
    validated to cut off cleanly rather than blocking on a slow/absent PTR).

.PARAMETER MaxAddressesWithoutForce
    Refuse to start a scan covering more addresses than this unless -Force
    is also passed. Defaults to 20,000,000 -- above the full built-in
    $DefaultSubnets list, so the default scope never needs -Force -- but
    still catches a scope blown up well past that by accident.

.PARAMETER Force
    Bypass the MaxAddressesWithoutForce guard.

.PARAMETER OutPath
    Output .xlsx path. Defaults to SMB-SWEEP-<timestamp>.xlsx. A companion
    .csv with the same name (Results sheet rows) is written alongside it.

.PARAMETER HostsCsv
    Skip Phase 1 entirely and reuse a CSV of already-discovered hosts
    (columns: Subnet,Host). Useful for re-running Phase 2 after a tune-up.

.EXAMPLE
    .\smb_share_sweep.ps1 -Subnets '192.168.5.0/24' -Threads 10 -BatchSize 100 -ShareThreads 20

.EXAMPLE
    .\smb_share_sweep.ps1 -Subnets '10.10.0.0/16','192.168.5.0/24' -ShareThreads 75

.EXAMPLE
    .\smb_share_sweep.ps1 -HostsCsv .\phase1_hosts.csv -ShareThreads 75

.EXAMPLE
    .\smb_share_sweep.ps1 -Subnets '10.0.0.0/8' -Force
#>

[CmdletBinding()]
param(
    [string[]]$Subnets,
    [int]$Threads = 20,
    [int]$BatchSize = 200,
    [int]$PortTimeoutMs = 1000,
    [int]$ShareThreads = 50,
    [int]$HostnameTimeoutMs = 1500,
    [int64]$MaxAddressesWithoutForce = 20000000,
    [switch]$Force,
    [string]$OutPath,
    [string]$HostsCsv
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Default subnet list -- edit freely; comment a line with '#' to exclude it.
# ---------------------------------------------------------------------------
$DefaultSubnets = @(
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "6.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/12",
    "9.0.0.0/8"
)

if (-not $Subnets -or $Subnets.Count -eq 0) { $Subnets = $DefaultSubnets }

# NOTE: the list of default/system share names lives inside $ShareEnumScriptBlock
# below (as $defaultShareNames), not here -- same reason as the formula-injection
# and reverse-DNS helpers: a RunspacePool worker doesn't inherit this scope.

$ReportTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $OutPath) {
    $OutPath = "SMB-SWEEP-$ReportTimestamp.xlsx"
}
$OutCsvPath = [System.IO.Path]::ChangeExtension($OutPath, "csv")

# ---------------------------------------------------------------------------
# Module check
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "[!] ImportExcel module not found. Install with:" -ForegroundColor Yellow
    Write-Host "      Install-Module ImportExcel -Scope CurrentUser" -ForegroundColor Yellow
    exit 1
}
Import-Module ImportExcel -ErrorAction Stop

# NOTE: the formula-injection neutralizer and the bounded reverse-DNS helper
# live inside $ShareEnumScriptBlock below (as ConvertTo-SafeCellValueLocal /
# Resolve-HostNameSafeLocal), not here -- a RunspacePool worker doesn't
# inherit the caller's functions, so anything Phase 2 needs has to be
# re-declared inside that scriptblock. Defining them a second time at this
# scope too would just be dead code.

# ---------------------------------------------------------------------------
# CIDR helpers
# ---------------------------------------------------------------------------
function ConvertTo-UInt32FromIp {
    param([string]$IpString)
    $bytes = [System.Net.IPAddress]::Parse($IpString).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IpFromUInt32 {
    param([uint32]$Value)
    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-CidrRange {
    <# Returns @{ Network=uint32; HostCount=int64; FirstHost=uint32; LastHost=uint32 } #>
    param([string]$Cidr)
    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) {
        throw "Malformed CIDR '$Cidr' -- expected IP/prefix, e.g. 10.0.0.0/8"
    }
    $maskBits = 0
    if (-not [int]::TryParse($parts[1], [ref]$maskBits) -or $maskBits -lt 0 -or $maskBits -gt 32) {
        throw "Malformed CIDR '$Cidr' -- prefix must be an integer 0-32"
    }
    try {
        $netInt = ConvertTo-UInt32FromIp $parts[0]
    } catch {
        throw "Malformed CIDR '$Cidr' -- '$($parts[0])' is not a valid IPv4 address"
    }
    $hostBits = 32 - $maskBits
    $blockSize = [int64][math]::Pow(2, $hostBits)
    # Avoid -shl on 0xFFFFFFFF: PowerShell's hex-literal type promotion makes
    # that shift/mask combination throw UInt32 conversion errors. Building the
    # mask by subtraction instead sidesteps the issue entirely.
    $maskVal = if ($maskBits -eq 0) { [uint32]0 } else { [uint32](4294967295 - ($blockSize - 1)) }
    $network = $netInt -band $maskVal
    if ($blockSize -le 2) {
        $first = $network
        $last = $network + $blockSize - 1
    } else {
        $first = $network + 1
        $last = $network + $blockSize - 2
    }
    return @{ Network = $network; HostCount = ($last - $first + 1); FirstHost = $first; LastHost = $last }
}

function Get-SubnetForIp {
    param([string]$Ip, [array]$SubnetRanges)
    $ipInt = ConvertTo-UInt32FromIp $Ip
    foreach ($s in $SubnetRanges) {
        if ($ipInt -ge $s.Range.FirstHost -and $ipInt -le $s.Range.LastHost) { return $s.Cidr }
    }
    return "unmatched"
}

# ---------------------------------------------------------------------------
# Generic runspace-pool batch runner (PS 5.1 compatible)
# ---------------------------------------------------------------------------
function Invoke-BatchedRunspaces {
    param(
        [array]$Batches,          # array of arrays -- each element is one unit of work
        [scriptblock]$ScriptBlock,
        [int]$MaxThreads,
        [string]$Activity,
        [int64]$TotalUnits,       # for progress math (e.g. total IPs, not total batches)
        [string]$BundleKey = $null  # when a batch is a hashtable bundle (extra params
                                     # packed alongside the work items, since a plain
                                     # RunspacePool has no $using: capture), this names
                                     # the key holding the actual array of work items
    )

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads, $iss, $Host)
    $pool.Open()

    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($batch in $Batches) {
        # UnitCount drives the progress bar math. A plain array's .Count is the
        # unit count directly. A bundle hashtable's .Count is its number of KEYS,
        # not the number of work items inside it -- that silently corrupts
        # progress math, so BundleKey must point at the actual items array.
        $unitCount = if ($batch -is [hashtable] -and $BundleKey -and $batch.ContainsKey($BundleKey)) {
            $batch[$BundleKey].Count
        } else {
            $batch.Count
        }
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock).AddArgument($batch)
        $handle = $ps.BeginInvoke()
        $jobs.Add([PSCustomObject]@{ Pipe = $ps; Handle = $handle; UnitCount = $unitCount })
    }

    $results = New-Object System.Collections.Generic.List[object]
    $unitsDone = 0
    $batchNum = 0
    foreach ($job in $jobs) {
        $out = $job.Pipe.EndInvoke($job.Handle)
        foreach ($o in $out) { $results.Add($o) }
        if ($job.Pipe.Streams.Error.Count -gt 0) {
            foreach ($e in $job.Pipe.Streams.Error) {
                Write-Verbose "Runspace error: $e"
            }
        }
        $job.Pipe.Dispose()
        $batchNum++
        $unitsDone += $job.UnitCount
        $pct = if ($TotalUnits -gt 0) { [math]::Min(100, [math]::Round(($unitsDone / $TotalUnits) * 100, 1)) } else { 0 }
        Write-Progress -Activity $Activity -Status "$unitsDone / $TotalUnits processed (batch $batchNum/$($jobs.Count))" -PercentComplete $pct
    }
    Write-Progress -Activity $Activity -Completed

    $pool.Close()
    $pool.Dispose()
    return $results
}

# ---------------------------------------------------------------------------
# Phase 1: port 445 sweep
# ---------------------------------------------------------------------------
function Get-CidrBatches {
    param([array]$SubnetRanges, [int]$BatchSize)
    $batches = New-Object System.Collections.Generic.List[object]
    foreach ($s in $SubnetRanges) {
        $r = $s.Range
        $buffer = New-Object System.Collections.Generic.List[string]
        for ($cur = $r.FirstHost; $cur -le $r.LastHost; $cur++) {
            $buffer.Add((ConvertTo-IpFromUInt32 $cur))
            if ($buffer.Count -ge $BatchSize) {
                # .Add() is a method call, not a pipeline -- passing the array
                # directly (no @(, ...) wrap) keeps it as one element, unlike
                # the array += case below which needs the wrap to not flatten.
                $batches.Add($buffer.ToArray())
                $buffer.Clear()
            }
        }
        if ($buffer.Count -gt 0) { $batches.Add($buffer.ToArray()) }
    }
    return $batches
}

# ---------------------------------------------------------------------------
# Phase 2: SMB share enumeration (current-user auth, no credentials)
# ---------------------------------------------------------------------------
$ShareEnumScriptBlock = {
    param($bundle)
    $hostBatch = $bundle.Hosts
    $hostnameTimeoutMs = $bundle.HostnameTimeoutMs

    # Re-declare types/functions inside the runspace -- separate runspaces
    # don't inherit the caller's session state in a RunspacePool.
    if (-not ("Win32Net.Api" -as [type])) {
        Add-Type -Namespace Win32Net -Name Api -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("NetApi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int NetShareEnum(
    string ServerName, int level, out System.IntPtr bufptr, int prefmaxlen,
    ref int entriesread, ref int totalentries, ref int resume_handle);
[System.Runtime.InteropServices.DllImport("NetApi32.dll")]
public static extern int NetApiBufferFree(System.IntPtr Buffer);
'@
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace Win32Net {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHARE_INFO_1 { public string shi1_netname; public uint shi1_type; public string shi1_remark; }
}
'@
    }

    # CSV/Excel formula injection (CWE-1236): Share name and Comment come from
    # NetShareEnum on hosts across the whole scope -- on a compromised or
    # untrusted box, an attacker fully controls those strings, and opening the
    # report in Excel/LibreOffice/Google Sheets is the tool's whole purpose.
    # Prefixing a leading quote onto any value starting with a formula-trigger
    # character forces plain-text interpretation. Same fix already applied in
    # sslspray.py / telnet_spray.py -- kept consistent here.
    function ConvertTo-SafeCellValueLocal {
        param($Value)
        if ($Value -is [string] -and $Value.Length -gt 0) {
            $c = $Value[0]
            if ($c -eq '=' -or $c -eq '+' -or $c -eq '-' -or $c -eq '@' -or $c -eq "`t" -or $c -eq "`r") {
                return "'" + $Value
            }
        }
        return $Value
    }

    function Resolve-HostNameSafeLocal {
        param([string]$IpAddress, [int]$TimeoutMs)
        try {
            $ar = [System.Net.Dns]::BeginGetHostEntry($IpAddress, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                return ([System.Net.Dns]::EndGetHostEntry($ar)).HostName
            }
            return ""
        } catch {
            return ""
        }
    }

    $defaultShareNames = @('ADMIN$','C$','D$','E$','IPC$','PRINT$','NETLOGON','SYSVOL')
    $stypeMap = @{0='disk'; 1='print'; 3='ipc'}

    $hostResults = New-Object System.Collections.Generic.List[object]
    $shareResults = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $hostBatch) {
        $target = $entry.Host
        $subnet = $entry.Subnet
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        $hostname = Resolve-HostNameSafeLocal -IpAddress $target -TimeoutMs $hostnameTimeoutMs

        $bufPtr = [System.IntPtr]::Zero
        $entriesRead = 0; $totalEntries = 0; $resumeHandle = 0
        $rc = [Win32Net.Api]::NetShareEnum($target, 1, [ref]$bufPtr, -1, [ref]$entriesRead, [ref]$totalEntries, [ref]$resumeHandle)

        $authSuccess = ($rc -eq 0)
        $authError = ""
        if (-not $authSuccess) {
            $authError = switch ($rc) {
                5    { "Access denied" }
                53   { "Host unreachable / RPC endpoint not found" }
                67   { "Network name not found" }
                1231 { "Network location unreachable" }
                1326 { "Logon failure" }
                1788 { "Trust relationship failure" }
                default { "Win32 error $rc" }
            }
        }

        $shareCount = 0
        try {
            if ($authSuccess -and $entriesRead -gt 0) {
                $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32Net.SHARE_INFO_1])
                $offset = $bufPtr.ToInt64()
                for ($i = 0; $i -lt $entriesRead; $i++) {
                    $itemPtr = [System.IntPtr]($offset + ($i * $structSize))
                    $item = [System.Runtime.InteropServices.Marshal]::PtrToStructure($itemPtr, [type][Win32Net.SHARE_INFO_1])

                    $rawType = $item.shi1_type -band 0x0FFFFFFF
                    $stype = if ($stypeMap.ContainsKey([int]$rawType)) { $stypeMap[[int]$rawType] } else { "unknown($rawType)" }
                    $isDefault = $defaultShareNames -contains $item.shi1_netname.ToUpper()

                    # UNC path is built for every share type (not just disk) -- it's valid
                    # syntax regardless, and the Results/CSV column is purely informational.
                    $uncPath = "\\$target\$($item.shi1_netname)"

                    $readable = $false
                    $readErr = ""
                    if ($stype -eq 'disk') {
                        try {
                            [void](Get-ChildItem -LiteralPath $uncPath -Force -ErrorAction Stop | Select-Object -First 1)
                            $readable = $true
                        } catch {
                            $readErr = $_.Exception.Message
                        }
                    }

                    $category = if ($readable -and -not $isDefault) { "Readable - Custom Share" }
                                elseif ($readable -and $isDefault) { "Readable - Default/System Share" }
                                else { "Not Readable" }

                    $shareResults.Add([PSCustomObject]@{
                        Subnet    = $subnet
                        Host      = $target
                        Hostname  = (ConvertTo-SafeCellValueLocal $hostname)
                        Share     = (ConvertTo-SafeCellValueLocal $item.shi1_netname)
                        UNCPath   = (ConvertTo-SafeCellValueLocal $uncPath)
                        ShareType = $stype
                        IsDefault = $isDefault
                        Comment   = (ConvertTo-SafeCellValueLocal $item.shi1_remark)
                        Readable  = $readable
                        Category  = $category
                        Error     = $readErr
                    })
                    $shareCount++
                }
            }
        } finally {
            # Guarantee the native buffer is freed even if marshalling throws
            # partway through (e.g. a malformed struct) -- otherwise this leaks.
            if ($bufPtr -ne [System.IntPtr]::Zero) { [void][Win32Net.Api]::NetApiBufferFree($bufPtr) }
        }

        $sw.Stop()
        $hostResults.Add([PSCustomObject]@{
            Subnet       = $subnet
            Host         = $target
            Hostname     = (ConvertTo-SafeCellValueLocal $hostname)
            Port445Open  = $true
            AuthSuccess  = $authSuccess
            AuthError    = $authError
            ShareCount   = $shareCount
            ScanTimeS    = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        })
    }

    return [PSCustomObject]@{ Hosts = $hostResults; Shares = $shareResults }
}

# ---------------------------------------------------------------------------
# Excel report -- styled to match the house convention used across the other
# sweep tools (sslspray.py / telnet_spray.py / quantum_readiness_spray.py):
# dark header row, thin gridlines, frozen header + autofilter on data sheets,
# an Overview narrative sheet with a color-coded category legend first.
# ---------------------------------------------------------------------------
$HeaderFill   = [System.Drawing.Color]::FromArgb(0x2C, 0x3E, 0x50)
$HeaderFont   = [System.Drawing.Color]::White
$BorderColor  = [System.Drawing.Color]::FromArgb(0xD5, 0xD8, 0xDC)
$FillReadableCustom  = [System.Drawing.Color]::FromArgb(0xD5, 0xF5, 0xE3)   # green
$FillReadableDefault = [System.Drawing.Color]::FromArgb(0xD6, 0xEA, 0xF8)   # blue
$FillNotReadable     = [System.Drawing.Color]::FromArgb(0xF2, 0xF3, 0xF4)   # light gray
$FillAuthFailed      = [System.Drawing.Color]::FromArgb(0xFA, 0xDB, 0xD8)   # light red

$ShareCategoryOrder = @("Readable - Custom Share", "Readable - Default/System Share", "Not Readable")
$ShareCategoryEmoji = @{
    "Readable - Custom Share"         = "[FOUND]"
    "Readable - Default/System Share" = "[ADMIN]"
    "Not Readable"                    = "[-]"
}
$ShareCategoryFill = @{
    "Readable - Custom Share"         = $FillReadableCustom
    "Readable - Default/System Share" = $FillReadableDefault
    "Not Readable"                    = $FillNotReadable
}
$ShareCategoryDescription = @{
    "Readable - Custom Share"         = "A non-default share the scanning account can list -- the primary finding this tool exists to surface. 'Custom' means it isn't on the Windows-created list (see the Default/System row below): someone deliberately created it, usually named for its purpose (Finance, Public, Backups, HR), with whatever ACL that admin chose. That's exactly why it matters -- a readable one means that specific person's permission choice let it be read, not that the scanning account happens to be an admin. Review contents for sensitive data."
    "Readable - Default/System Share" = "ADMIN`$, C`$, D`$/E`$ (drive roots), IPC`$, PRINT`$, plus NETLOGON/SYSVOL on domain controllers -- created automatically by Windows on every machine, not something an admin chose to set up. Reading them (besides NETLOGON/SYSVOL) normally requires local-administrator-equivalent rights, so 'readable' here mostly just confirms the scanning account's own privilege level on that host. Expected on some hosts, still worth confirming is intended everywhere else it shows up."
    "Not Readable"                    = "Share exists but Get-ChildItem was denied or errored (ACL, disabled share, etc.)."
}

function Build-Workbook {
    param($Subnets, $SubnetRanges, $HostRows, $ShareRows, $ScanMeta, $OutPath)

    if (Test-Path $OutPath) { Remove-Item $OutPath -Force }

    $pkg = Open-ExcelPackage -Path $OutPath -Create

    # ---- Overview sheet ----
    $ov = Add-Worksheet -ExcelPackage $pkg -WorksheetName "Overview"
    $ov.View.ShowGridLines = $false
    $ov.Column(1).Width = 36
    $ov.Column(2).Width = 70
    $ov.Column(3).Width = 20
    $ov.Column(4).Width = 28
    $ov.Column(5).Width = 28
    $ov.Column(6).Width = 15

    $r = 1
    $ov.Cells[$r,1].Value = "SMB Share Sweep -- Executive Overview"
    $ov.Cells[$r,1].Style.Font.Bold = $true
    $ov.Cells[$r,1].Style.Font.Size = 14
    $r += 2

    $ov.Cells[$r,1].Value = "Scan date:"; $ov.Cells[$r,2].Value = $ScanMeta.ScanDate; $r++
    $ov.Cells[$r,1].Value = "Subnets scanned:"; $ov.Cells[$r,2].Value = $Subnets.Count; $r++
    $r++

    $ov.Cells[$r,1].Value = "Category"; $ov.Cells[$r,2].Value = "What it means"
    Set-ExcelRange -Range $ov.Cells[$r,1,$r,2] -BackgroundColor $HeaderFill -FontColor $HeaderFont -Bold
    $r++
    foreach ($cat in $ShareCategoryOrder) {
        $desc = $ShareCategoryDescription[$cat]
        $ov.Cells[$r,1].Value = "$($ShareCategoryEmoji[$cat]) $cat"
        $ov.Cells[$r,2].Value = $desc
        Set-ExcelRange -Range $ov.Cells[$r,1] -BackgroundColor $ShareCategoryFill[$cat] -Bold
        Set-ExcelRange -Range $ov.Cells[$r,2] -WrapText
        $ov.Cells[$r,1].Style.VerticalAlignment = 'Top'
        $ov.Cells[$r,2].Style.VerticalAlignment = 'Top'
        # Column B is 70 (Excel width units, ~chars/line). Fixed-height rows
        # looked cramped/overlapping once descriptions got long -- size each
        # row to its own text instead of guessing one height for all three.
        $wrapLines = [math]::Max(1, [math]::Ceiling($desc.Length / 68.0))
        $ov.Row($r).Height = [math]::Max(30, ($wrapLines * 15) + 8)
        $r++
    }
    $r++

    $totalShares = $ShareRows.Count
    $catCounts = @{}
    foreach ($cat in $ShareCategoryOrder) { $catCounts[$cat] = 0 }
    foreach ($row in $ShareRows) { $catCounts[$row.Category]++ }

    $ov.Cells[$r,1].Value = "Scan Summary"; $ov.Cells[$r,1].Style.Font.Bold = $true; $ov.Cells[$r,1].Style.Font.Size = 12; $r++
    $ov.Cells[$r,1].Value = "Total hosts contacted:"; $ov.Cells[$r,2].Value = $HostRows.Count; $r++
    $ov.Cells[$r,1].Value = "Hosts enumerated successfully:"; $ov.Cells[$r,2].Value = @($HostRows | Where-Object AuthSuccess).Count; $r++
    $ov.Cells[$r,1].Value = "Total shares found:"; $ov.Cells[$r,2].Value = $totalShares; $r++
    $ov.Cells[$r,1].Value = "Category"; $ov.Cells[$r,2].Value = "Count"; $ov.Cells[$r,3].Value = "% of Total"
    Set-ExcelRange -Range $ov.Cells[$r,1,$r,3] -Bold
    $r++
    foreach ($cat in $ShareCategoryOrder) {
        $pct = if ($totalShares -gt 0) { [math]::Round(($catCounts[$cat] / $totalShares) * 100.0, 1) } else { 0 }
        $ov.Cells[$r,1].Value = "$($ShareCategoryEmoji[$cat]) $cat"
        $ov.Cells[$r,2].Value = $catCounts[$cat]
        $ov.Cells[$r,3].Value = $pct
        $ov.Cells[$r,3].Style.Numberformat.Format = "0.0"
        Set-ExcelRange -Range $ov.Cells[$r,1] -BackgroundColor $ShareCategoryFill[$cat]
        $r++
    }
    $r++

    # ---- Top Hosts -- most exposed (sorted by readable CUSTOM shares first,
    # since a readable custom share means ordinary access can see it; a
    # readable default/admin share mainly reflects the scanning account's own
    # privilege, not necessarily what "anyone" could reach) ----
    $hostAgg = @{}
    foreach ($row in $ShareRows) {
        if (-not $hostAgg.ContainsKey($row.Host)) {
            $hostAgg[$row.Host] = [PSCustomObject]@{
                Host = $row.Host; Hostname = $row.Hostname; Subnet = $row.Subnet
                CustomReadable = 0; DefaultReadable = 0; TotalShares = 0
            }
        }
        $agg = $hostAgg[$row.Host]
        $agg.TotalShares++
        if ($row.Category -eq "Readable - Custom Share") { $agg.CustomReadable++ }
        elseif ($row.Category -eq "Readable - Default/System Share") { $agg.DefaultReadable++ }
    }
    $topHosts = $hostAgg.Values |
        Where-Object { ($_.CustomReadable + $_.DefaultReadable) -gt 0 } |
        Sort-Object -Property @{Expression='CustomReadable';Descending=$true}, @{Expression='DefaultReadable';Descending=$true} |
        Select-Object -First 20

    $ov.Cells[$r,1].Value = "Top 20 Hosts -- Most Readable Shares"; $ov.Cells[$r,1].Style.Font.Bold = $true; $ov.Cells[$r,1].Style.Font.Size = 12; $r++
    if ($topHosts.Count -eq 0) {
        $ov.Cells[$r,1].Value = "No readable shares found."
        $r++
    } else {
        $thHeaders = @("Host","Hostname","Subnet","Readable (Custom)","Readable (Default/Admin)","Total Shares")
        for ($c = 0; $c -lt $thHeaders.Count; $c++) { $ov.Cells[$r,($c+1)].Value = $thHeaders[$c] }
        Set-ExcelRange -Range $ov.Cells[$r,1,$r,$thHeaders.Count] -Bold
        $r++
        foreach ($h in $topHosts) {
            $ov.Cells[$r,1].Value = $h.Host
            $ov.Cells[$r,2].Value = $h.Hostname
            $ov.Cells[$r,3].Value = $h.Subnet
            $ov.Cells[$r,4].Value = $h.CustomReadable
            $ov.Cells[$r,5].Value = $h.DefaultReadable
            $ov.Cells[$r,6].Value = $h.TotalShares
            if ($h.CustomReadable -gt 0) {
                Set-ExcelRange -Range $ov.Cells[$r,1,$r,$thHeaders.Count] -BackgroundColor $FillReadableCustom
            }
            $r++
        }
    }
    $r++

    $ov.Cells[$r,1].Value = "Subnet Breakdown"; $ov.Cells[$r,1].Style.Font.Bold = $true; $ov.Cells[$r,1].Style.Font.Size = 12; $r++
    $subnetAgg = @{}
    foreach ($row in $ShareRows) {
        if (-not $subnetAgg.ContainsKey($row.Subnet)) {
            $subnetAgg[$row.Subnet] = [PSCustomObject]@{ Subnet = $row.Subnet; Total = 0; CustomReadable = 0; DefaultReadable = 0 }
        }
        $subnetAgg[$row.Subnet].Total++
        if ($row.Category -eq "Readable - Custom Share") { $subnetAgg[$row.Subnet].CustomReadable++ }
        elseif ($row.Category -eq "Readable - Default/System Share") { $subnetAgg[$row.Subnet].DefaultReadable++ }
    }
    $sbHeaders = @("Subnet","Total Shares","Readable (Custom)","Readable (Default/Admin)")
    for ($c = 0; $c -lt $sbHeaders.Count; $c++) { $ov.Cells[$r,($c+1)].Value = $sbHeaders[$c] }
    Set-ExcelRange -Range $ov.Cells[$r,1,$r,$sbHeaders.Count] -Bold
    $r++
    foreach ($s in ($subnetAgg.Values | Sort-Object -Property @{Expression='CustomReadable';Descending=$true}, Subnet)) {
        $ov.Cells[$r,1].Value = $s.Subnet
        $ov.Cells[$r,2].Value = $s.Total
        $ov.Cells[$r,3].Value = $s.CustomReadable
        $ov.Cells[$r,4].Value = $s.DefaultReadable
        $r++
    }
    $r++

    # ---- Totals -- grand total across every subnet/host, any share that can
    # be opened and read, custom or default/system alike ----
    $totalReadableCustom = @($ShareRows | Where-Object { $_.Category -eq "Readable - Custom Share" }).Count
    $totalReadableDefault = @($ShareRows | Where-Object { $_.Category -eq "Readable - Default/System Share" }).Count
    $totalReadableAll = $totalReadableCustom + $totalReadableDefault
    $ov.Cells[$r,1].Value = "Total Readable Shares (All):"; $ov.Cells[$r,1].Style.Font.Bold = $true
    $ov.Cells[$r,2].Value = $totalReadableAll; $ov.Cells[$r,2].Style.Font.Bold = $true
    $r++
    $ov.Cells[$r,1].Value = "  Readable (Custom):"; $ov.Cells[$r,2].Value = $totalReadableCustom; $r++
    $ov.Cells[$r,1].Value = "  Readable (Default/Admin):"; $ov.Cells[$r,2].Value = $totalReadableDefault; $r++

    # ---- Results sheet (per-share) ----
    $wr = Add-Worksheet -ExcelPackage $pkg -WorksheetName "Results"
    $wr.View.ShowGridLines = $false
    $resultHeaders = @("Subnet","Host","Hostname","Share","UNCPath","ShareType","IsDefault","Comment","Readable","Category","Error")
    $resultWidths  = @(18, 16, 26, 16, 28, 10, 10, 40, 10, 28, 40)
    for ($c = 0; $c -lt $resultHeaders.Count; $c++) {
        $wr.Cells[1, ($c+1)].Value = $resultHeaders[$c]
        $wr.Column($c+1).Width = $resultWidths[$c]
    }
    Set-ExcelRange -Range $wr.Cells[1,1,1,$resultHeaders.Count] -BackgroundColor $HeaderFill -FontColor $HeaderFont -Bold -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor

    $sortedShares = $ShareRows | Sort-Object Subnet, Host, Share
    $rowIdx = 2
    foreach ($row in $sortedShares) {
        $vals = @($row.Subnet, $row.Host, $row.Hostname, $row.Share, $row.UNCPath, $row.ShareType, $row.IsDefault, $row.Comment, $row.Readable, "$($ShareCategoryEmoji[$row.Category]) $($row.Category)", $row.Error)
        for ($c = 0; $c -lt $vals.Count; $c++) { $wr.Cells[$rowIdx, ($c+1)].Value = $vals[$c] }
        $fillColor = $ShareCategoryFill[$row.Category]
        if ($fillColor) {
            Set-ExcelRange -Range $wr.Cells[$rowIdx,1,$rowIdx,$resultHeaders.Count] -BackgroundColor $fillColor -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor -WrapText
        } else {
            Set-ExcelRange -Range $wr.Cells[$rowIdx,1,$rowIdx,$resultHeaders.Count] -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor -WrapText
        }
        $rowIdx++
    }
    if ($sortedShares.Count -gt 0) {
        $wr.View.FreezePanes(2,1)
        $wr.Cells[1,1,($rowIdx-1),$resultHeaders.Count].AutoFilter = $true
    }

    # ---- Hosts sheet ----
    $hs = Add-Worksheet -ExcelPackage $pkg -WorksheetName "Hosts"
    $hs.View.ShowGridLines = $false
    $hostHeaders = @("Subnet","Host","Hostname","Port445Open","AuthSuccess","AuthError","ShareCount","ScanTimeS")
    $hostWidths  = @(18, 16, 26, 12, 12, 32, 10, 10)
    for ($c = 0; $c -lt $hostHeaders.Count; $c++) {
        $hs.Cells[1, ($c+1)].Value = $hostHeaders[$c]
        $hs.Column($c+1).Width = $hostWidths[$c]
    }
    Set-ExcelRange -Range $hs.Cells[1,1,1,$hostHeaders.Count] -BackgroundColor $HeaderFill -FontColor $HeaderFont -Bold -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor

    $sortedHosts = $HostRows | Sort-Object Subnet, Host
    $rowIdx = 2
    foreach ($row in $sortedHosts) {
        $vals = @($row.Subnet, $row.Host, $row.Hostname, $row.Port445Open, $row.AuthSuccess, $row.AuthError, $row.ShareCount, $row.ScanTimeS)
        for ($c = 0; $c -lt $vals.Count; $c++) { $hs.Cells[$rowIdx, ($c+1)].Value = $vals[$c] }
        if (-not $row.AuthSuccess) {
            Set-ExcelRange -Range $hs.Cells[$rowIdx,1,$rowIdx,$hostHeaders.Count] -BackgroundColor $FillAuthFailed -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor
        } else {
            Set-ExcelRange -Range $hs.Cells[$rowIdx,1,$rowIdx,$hostHeaders.Count] -BorderTop Thin -BorderBottom Thin -BorderLeft Thin -BorderRight Thin -BorderColor $BorderColor
        }
        $rowIdx++
    }
    if ($sortedHosts.Count -gt 0) {
        $hs.View.FreezePanes(2,1)
        $hs.Cells[1,1,($rowIdx-1),$hostHeaders.Count].AutoFilter = $true
    }

    # ---- Detailed Stats (formula-driven, per subnet) ----
    $wsD = Add-Worksheet -ExcelPackage $pkg -WorksheetName "Detailed Stats"
    $dHeaders = @("Subnet","TotalAddresses","HostsUp","HostsAuthenticated","AuthFailures",
                  "TotalShares","DefaultShares","CustomShares","ReadableShares","CustomReadable")
    for ($c = 0; $c -lt $dHeaders.Count; $c++) { $wsD.Cells[1, ($c+1)].Value = $dHeaders[$c] }
    Set-ExcelRange -Range $wsD.Cells[1,1,1,$dHeaders.Count] -Bold

    $firstDataRow = 2
    for ($i = 0; $i -lt $Subnets.Count; $i++) {
        $row = $firstDataRow + $i
        $subnet = $Subnets[$i]
        $range = $SubnetRanges[$i].Range
        $wsD.Cells[$row, 1].Value = $subnet
        $wsD.Cells[$row, 2].Value = [int64]$range.HostCount
        $wsD.Cells[$row, 3].Formula = "COUNTIF(Hosts!A:A,A$row)"
        $wsD.Cells[$row, 4].Formula = "COUNTIFS(Hosts!A:A,A$row,Hosts!E:E,TRUE)"
        $wsD.Cells[$row, 5].Formula = "C$row-D$row"
        $wsD.Cells[$row, 6].Formula = "COUNTIF(Results!A:A,A$row)"
        # Results columns post-UNCPath insert: A=Subnet G=IsDefault I=Readable
        $wsD.Cells[$row, 7].Formula = "COUNTIFS(Results!A:A,A$row,Results!G:G,TRUE)"
        $wsD.Cells[$row, 8].Formula = "F$row-G$row"
        $wsD.Cells[$row, 9].Formula = "COUNTIFS(Results!A:A,A$row,Results!I:I,TRUE)"
        # NOTE: tested and confirmed EPPlus's own bundled formula-calculation
        # engine (used below for Close-ExcelPackage -Calculate) can cache a
        # wrong value for this specific shape -- a text-equality criteria pair
        # combined with two boolean criteria pairs in one COUNTIFS call. No
        # criteria ordering reliably works around it (tried; still wrong on a
        # richer dataset), and it's an EPPlus limitation, not a formula error:
        # the formula itself is standard, valid Excel syntax. This is harmless
        # in practice -- Close-ExcelPackage sets fullCalcOnLoad="1" (verified
        # in the generated file), which forces Excel/LibreOffice to recompute
        # every formula with their own correct engine the instant the file is
        # opened, overwriting whatever EPPlus cached.
        $wsD.Cells[$row, 10].Formula = "COUNTIFS(Results!A:A,A$row,Results!G:G,FALSE,Results!I:I,TRUE)"
    }
    $lastSubnetRow = $firstDataRow + $Subnets.Count - 1
    $totalRow = $lastSubnetRow + 1
    $wsD.Cells[$totalRow, 1].Value = "TOTAL"
    Set-ExcelRange -Range $wsD.Cells[$totalRow,1] -Bold
    for ($col = 2; $col -le 10; $col++) {
        $letter = [char](64 + $col)
        $wsD.Cells[$totalRow, $col].Formula = "SUM($letter$firstDataRow`:$letter$lastSubnetRow)"
    }
    Set-ExcelRange -Range $wsD.Cells[$totalRow,1,$totalRow,10] -Bold
    $wsD.Cells[$wsD.Dimension.Address].AutoFitColumns()

    $pkg.Workbook.Worksheets.MoveToStart("Overview")
    Close-ExcelPackage $pkg -Calculate
}

# ===========================================================================
# MAIN
# ===========================================================================
$startTime = Get-Date

Write-Host "[*] $($Subnets.Count) subnet(s) in scope:" -ForegroundColor Cyan
$subnetRanges = @()
$totalAddresses = 0
foreach ($s in $Subnets) {
    try {
        $range = Get-CidrRange -Cidr $s
    } catch {
        Write-Host "[!] $_" -ForegroundColor Red
        exit 1
    }
    $subnetRanges += [PSCustomObject]@{ Cidr = $s; Range = $range }
    $totalAddresses += $range.HostCount
    Write-Host ("      {0}  (~{1:N0} addresses)" -f $s, $range.HostCount)
}
Write-Host ("[*] Total addresses in scope: {0:N0}" -f $totalAddresses) -ForegroundColor Cyan

if (-not $HostsCsv -and -not $Force -and $totalAddresses -gt $MaxAddressesWithoutForce) {
    Write-Host ("[!] Scope covers {0:N0} addresses, which exceeds the {1:N0}-address guard." -f $totalAddresses, $MaxAddressesWithoutForce) -ForegroundColor Red
    Write-Host "[!] This tool does TCP connect scans, not raw SYN packets -- a scope this size can take hours." -ForegroundColor Red
    Write-Host "[!] Test on a /24 first, narrow -Subnets, or re-run with -Force to proceed anyway." -ForegroundColor Red
    exit 1
}

# ---- Phase 1: port 445 sweep ----
$liveHostEntries = New-Object System.Collections.Generic.List[object]

if ($HostsCsv) {
    Write-Host "[*] Reusing host list from $HostsCsv" -ForegroundColor Cyan
    Import-Csv $HostsCsv | ForEach-Object {
        $liveHostEntries.Add([PSCustomObject]@{ Subnet = $_.Subnet; Host = $_.Host })
    }
} else {
    Write-Host "[*] Building IP batches (batch size $BatchSize)..." -ForegroundColor Cyan
    $batches = Get-CidrBatches -SubnetRanges $subnetRanges -BatchSize $BatchSize
    Write-Host "[*] $($batches.Count) batch(es) to scan across $Threads runspace(s)" -ForegroundColor Cyan

    # Runspaces in a plain RunspacePool don't capture $using: the way
    # ForEach-Object -Parallel does, so bundle the timeout with each batch.
    $batchesWithTimeout = $batches | ForEach-Object { @{ Ips = $_; Timeout = $PortTimeoutMs } }

    $portScanWrapper = {
        param($bundle)
        $ipBatch = $bundle.Ips
        $timeoutMs = $bundle.Timeout
        $pending = @{}
        foreach ($ip in $ipBatch) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $ar = $client.BeginConnect($ip, 445, $null, $null)
                $pending[$ip] = @{ Client = $client; Ar = $ar }
            } catch {
                if ($client) { $client.Dispose() }
            }
        }
        Start-Sleep -Milliseconds $timeoutMs
        $open = @()
        foreach ($ip in $pending.Keys) {
            $entry = $pending[$ip]
            $c = $entry.Client
            try {
                if ($entry.Ar.IsCompleted -and $c.Connected) {
                    $c.EndConnect($entry.Ar)
                    $open += $ip
                }
            } catch {
            } finally {
                $c.Close()
            }
        }
        return $open
    }

    $openIps = Invoke-BatchedRunspaces -Batches $batchesWithTimeout -ScriptBlock $portScanWrapper `
        -MaxThreads $Threads -Activity "Port 445 sweep" -TotalUnits $totalAddresses -BundleKey 'Ips'

    foreach ($ip in $openIps) {
        $subnet = Get-SubnetForIp -Ip $ip -SubnetRanges $subnetRanges
        $liveHostEntries.Add([PSCustomObject]@{ Subnet = $subnet; Host = $ip })
    }

    # Save intermediate host list so a crash in Phase 2 doesn't lose Phase 1 work
    $phase1CsvPath = "phase1_hosts_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)
    $liveHostEntries | Export-Csv -Path $phase1CsvPath -NoTypeInformation
    Write-Host "[*] Phase 1 host list saved to $phase1CsvPath" -ForegroundColor Cyan
}

Write-Host ("[*] Hosts with 445/tcp open: {0}" -f $liveHostEntries.Count) -ForegroundColor Cyan
if ($liveHostEntries.Count -eq 0) {
    Write-Host "[!] No live hosts found -- nothing to enumerate. Exiting." -ForegroundColor Yellow
    exit 0
}

# ---- Phase 2: SMB share enumeration ----
Write-Host "[*] Enumerating shares (current-user auth, no credentials needed)..." -ForegroundColor Cyan

$shareBatchSize = [math]::Max(1, [math]::Ceiling($liveHostEntries.Count / ($ShareThreads * 4)))
$hostBatches = @()
for ($i = 0; $i -lt $liveHostEntries.Count; $i += $shareBatchSize) {
    $end = [math]::Min($i + $shareBatchSize, $liveHostEntries.Count) - 1
    $hostBatches += @(, @($liveHostEntries[$i..$end]))
}

# Runspaces in a plain RunspacePool don't capture $using: the way
# ForEach-Object -Parallel does, so bundle the hostname timeout with each
# batch -- same pattern already used for the port-scan phase's timeout.
$hostBatchBundles = $hostBatches | ForEach-Object { @{ Hosts = $_; HostnameTimeoutMs = $HostnameTimeoutMs } }

$shareResultsRaw = Invoke-BatchedRunspaces -Batches $hostBatchBundles -ScriptBlock $ShareEnumScriptBlock `
    -MaxThreads $ShareThreads -Activity "SMB share enumeration" -TotalUnits $liveHostEntries.Count -BundleKey 'Hosts'

$allHostRows = New-Object System.Collections.Generic.List[object]
$allShareRows = New-Object System.Collections.Generic.List[object]
foreach ($r in $shareResultsRaw) {
    foreach ($h in $r.Hosts) { $allHostRows.Add($h) }
    foreach ($s in $r.Shares) { $allShareRows.Add($s) }
}

$elapsed = (Get-Date) - $startTime
$scanMeta = [PSCustomObject]@{
    ScanDate = (Get-Date).ToString("yyyy-MM-dd HH:mm")
}

Write-Host "[*] Building Excel report..." -ForegroundColor Cyan
Build-Workbook -Subnets $Subnets -SubnetRanges $subnetRanges -HostRows $allHostRows `
    -ShareRows $allShareRows -ScanMeta $scanMeta -OutPath $OutPath

# Companion CSV -- same rows/order as the Results sheet, same convention as
# the Python sibling scripts (one wide CSV + one .xlsx per run).
$allShareRows | Sort-Object Subnet, Host, Share | Export-Csv -Path $OutCsvPath -NoTypeInformation

$authOk = @($allHostRows | Where-Object AuthSuccess).Count
$readableOk = @($allShareRows | Where-Object Readable).Count
Write-Host ("[*] Done in {0:N1}s -> {1}" -f $elapsed.TotalSeconds, $OutPath) -ForegroundColor Green
Write-Host ("[*] CSV companion -> {0}" -f $OutCsvPath) -ForegroundColor Green
Write-Host ("[*] Quick summary: {0} hosts contacted, {1} enumerated successfully, {2} share instances, {3} readable." -f `
    $allHostRows.Count, $authOk, $allShareRows.Count, $readableOk) -ForegroundColor Green
