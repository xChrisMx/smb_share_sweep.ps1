<#
.SYNOPSIS
    Single-server SMB "open share" check: lists the shares on a server that are
    actually accessible (openable) from the account running the script -- plus
    any share that could not be tested -- and writes an email-ready report
    (.txt, .html, .csv).

.DESCRIPTION
    Standalone one-off tool (separate from the subnet-wide smb_share_sweep.ps1;
    shares its approach -- current logon token, no credentials, read-only --
    but no code or files). Aimed at ONE server at a time: the "I have a server
    with a ton of shares and can't click through them all in Explorer" case.

    Run it with no arguments and it asks:

        Input server name (e.g. ozssu02.muv.is.keysight.com):

    Paste a server name (FQDN, short name or IPv4). Pasting a UNC such as
    \\ozssu02.muv.is.keysight.com\9063_LAB also works -- the share part is
    stripped (spaces inside a UNC/URL belong to the share name, they do not
    separate servers). Several servers can be pasted on one line, separated by
    commas (or spaces for bare host names), and the prompt repeats until you
    press Enter on an empty line.

    What it does per server:
      1. Resolves the name and checks TCP/445 (bounded timeouts, so an
         unreachable server fails fast with a clear reason).
      2. Lists every share with NetShareEnum (Win32 API, current logon token).
      3. Opens each disk share root read-only (directory listing) in parallel,
         with a hard per-share timeout so one dead DFS target / offline volume
         cannot stall the run -- it is reported as "could not be tested".
      4. For every share that opened, reads the root folder's NTFS owner and
         ACL and flags whether Everyone / Authenticated Users / Domain Users /
         BUILTIN\Users / NETWORK / Anonymous / Guests have access, and whether
         that access includes write/modify/full control:
             BROAD-WRITE  broad group can write  (fix first)
             BROAD-READ   broad group can read
             LIMITED      no broad group on the ACL (a large group can still
                          be listed -- review the ACL in the .csv/.html)
             UNKNOWN      root ACL could not be read
             DEFAULT      Windows default share (C$, ADMIN$, ...): not rated
      5. Prints the accessible shares to the terminal (Custom shares first,
         worst exposure first; default/system shares last) plus any shares
         that could not be tested (unknown, NOT closed), then writes the same
         list to <OutDir>\<server>\OpenShares_<server>_<time>.txt (paste-ready),
         .html (paste into Outlook as a table) and .csv (attach / open in
         Excel) -- one folder per server. -ShowAll adds the denied and
         non-folder shares.

    USE ONLY ON SERVERS YOU ARE AUTHORIZED TO ASSESS.

    SAFETY NOTES
      - Read-only. Nothing is ever created, written, modified or deleted on a
        remote share; the check is "can the root folder be listed".
      - No credentials are collected, stored or transmitted -- the script
        rides your current Windows logon session.
      - "Accessible" means accessible to THE ACCOUNT RUNNING THE SCRIPT. For an
        "open to all staff" view, run it from a standard (non-admin) domain
        user session -- as an admin nearly every share is readable. The script
        warns when the account is in Domain Admins / Enterprise Admins /
        Schema Admins, and again per server whenever C$/ADMIN$ can be opened
        (proof of admin rights on that server).
      - Exposure flags come from the NTFS ACL on the share root. Share-level
        permissions and deny entries are not evaluated (that needs admin on
        the server), so BROAD-* is a strong indicator, not a proof of write
        access.
      - Share names / comments come from the remote server, so they are
        neutralized against CSV/Excel formula injection (CWE-1236) and
        HTML-encoded in the HTML report; control characters are stripped.
      - KNOWN LIMITATION: a blocked Win32 SMB call cannot be killed from
        PowerShell. Here a timed-out share is reported and abandoned (its
        worker thread is left to give up on its own OS-level timeout) instead
        of stalling the report.

.PARAMETER Server
    One or more server names (FQDN, short name or IPv4). If omitted (and no
    -ServerFile), the script prompts for it.

.PARAMETER ServerFile
    Text file with one server per line ('#' starts a comment).

.PARAMETER OutDir
    Root folder for the reports. Default: a "Reports" folder next to the script.
    Every server gets its own subfolder named after it, e.g.
        Reports\ozssu02.muv.is.keysight.com\OpenShares_ozssu02.muv.is.keysight.com_20261015_141200.txt
    so repeated runs and many servers stay organised (files are timestamped,
    nothing is ever overwritten).

.PARAMETER ShareThreads
    Concurrent workers probing shares (default 16).

.PARAMETER ShareTimeoutSec
    Per-share timeout in seconds (default 20). A share that does not answer
    in this time is reported as "Timeout" (could not be tested).

.PARAMETER PortTimeoutMs
    Timeout for the TCP/445 reachability check and DNS lookup (default 3000).

.PARAMETER MaxItemsCounted
    Top-level items are counted up to this number per share (default 1000;
    shown as "1000+" when there are more).

.PARAMETER SampleCount
    Also record the names of the first N top-level entries of each accessible
    share (default 0 = off). Off by default because file/folder names can
    themselves be sensitive and these reports get emailed.

.PARAMETER ShowAll
    Also list the shares that are NOT accessible and the ones that are not
    folder shares (terminal, txt, html, csv). Default: accessible shares only,
    plus any shares that COULD NOT BE TESTED (offline / timeout / error) --
    those are unknown, not closed, so they are never hidden.

.PARAMETER NoReport
    Terminal output only; do not write report files.

.NOTES
    Exit codes: 0 = finished (including quitting at the prompt);
                1 = a server could not be checked (DNS / TCP 445 / share list),
                    or no valid server / bad -ServerFile / bad -OutDir;
                2 = scan finished but the report files could not be written.
    If probes had to be abandoned (hung shares), a powershell.exe started with
    "-File" may take up to ~1 minute to close; an interactive session returns
    immediately.

.EXAMPLE
    .\SMB_oneoff_sweep.ps1
    (prompts: Input server name)

.EXAMPLE
    .\SMB_oneoff_sweep.ps1 ozssu02.muv.is.keysight.com

.EXAMPLE
    .\SMB_oneoff_sweep.ps1 -ServerFile .\servers.txt -OutDir C:\Temp\share-audit

.EXAMPLE
    .\SMB_oneoff_sweep.ps1 ozssu02.muv.is.keysight.com -ShowAll -SampleCount 5
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Server,
    [string]$ServerFile,
    [string]$OutDir,
    [ValidateRange(1, 64)]      [int]$ShareThreads    = 16,
    [ValidateRange(3, 300)]     [int]$ShareTimeoutSec = 20,
    [ValidateRange(200, 30000)] [int]$PortTimeoutMs   = 3000,
    [ValidateRange(1, 100000)]  [int]$MaxItemsCounted = 1000,
    [ValidateRange(0, 50)]      [int]$SampleCount     = 0,
    [switch]$ShowAll,
    [switch]$NoReport
)

$ErrorActionPreference = 'Stop'

$ToolName    = 'SMB One-Off Sweep'
$ToolVersion = '1.0'

# Windows-created shares. Everything else is a "Custom" share someone set up on
# purpose.
$DefaultShareRegex = '^(?:[A-Za-z]\$|ADMIN\$|IPC\$|PRINT\$|FAX\$|NETLOGON|SYSVOL)$'

# Probe outcomes that mean "unknown" (neither open nor proven closed).
$CantStatuses = @('Unavailable', 'Error', 'Timeout', 'NotTested')

# Count of probes abandoned because a share hung (see Invoke-ShareAccessTests).
$script:AbandonedProbes = 0

# ---------------------------------------------------------------------------
# Native share enumeration (NetShareEnum level 1 -- same API as the sibling
# script). All pointer math lives in C# so PowerShell only sees a plain list.
# ---------------------------------------------------------------------------
if (-not ('SmbOpenShare.NetApi' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SmbOpenShare {
    public class ShareEntry {
        public string Name;
        public uint   Type;
        public string Remark;
    }

    public class ShareEnumResult {
        public int ErrorCode;
        public List<ShareEntry> Shares = new List<ShareEntry>();
    }

    public static class NetApi {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHARE_INFO_1 {
            public string shi1_netname;
            public uint   shi1_type;
            public string shi1_remark;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(string servername, int level, out IntPtr bufptr,
            int prefmaxlen, out int entriesread, out int totalentries, ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr buffer);

        public static ShareEnumResult EnumerateShares(string server) {
            ShareEnumResult result = new ShareEnumResult();
            IntPtr buf = IntPtr.Zero;
            int read = 0, total = 0, resume = 0;
            result.ErrorCode = NetShareEnum(server, 1, out buf, -1, out read, out total, ref resume);
            try {
                if ((result.ErrorCode == 0 || result.ErrorCode == 234) && buf != IntPtr.Zero) {
                    int size = Marshal.SizeOf(typeof(SHARE_INFO_1));
                    for (int i = 0; i < read; i++) {
                        IntPtr p = new IntPtr(buf.ToInt64() + (long)i * size);
                        SHARE_INFO_1 s = (SHARE_INFO_1)Marshal.PtrToStructure(p, typeof(SHARE_INFO_1));
                        ShareEntry e = new ShareEntry();
                        e.Name   = s.shi1_netname;
                        e.Type   = s.shi1_type;
                        e.Remark = s.shi1_remark;
                        result.Shares.Add(e);
                    }
                }
            } finally {
                // Always free the native buffer, even if marshalling throws.
                if (buf != IntPtr.Zero) NetApiBufferFree(buf);
            }
            return result;
        }
    }
}
'@
}

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Get-RealException {
    # PowerShell wraps .NET exceptions thrown from method calls in
    # MethodInvocationException -- unwrap to the real one.
    param($ErrorOrException)
    $e = $ErrorOrException
    if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
    while ($e -and $e.InnerException -and ($e -is [System.Management.Automation.RuntimeException])) {
        $e = $e.InnerException
    }
    return $e
}

function ConvertTo-SafeCellValue {
    # CSV/Excel formula injection (CWE-1236): share names, comments, owner and
    # ACL text come from the remote server. A leading quote forces plain text.
    param($Value)
    if ($Value -is [string] -and $Value.Length -gt 0) {
        $c = $Value[0]
        if ($c -eq '=' -or $c -eq '+' -or $c -eq '-' -or $c -eq '@' -or $c -eq "`t" -or $c -eq "`r") {
            return "'" + $Value
        }
    }
    return $Value
}

function ConvertTo-ServerName {
    # Accepts what people actually paste: FQDN, \\server, \\server\share,
    # smb://server/share, quoted, trailing dot, :445 ...
    param([string]$Raw)
    $s = $Raw.Trim().Trim([char[]]@('"', "'", '<', '>')).Trim()
    $s = $s -replace '^[A-Za-z][A-Za-z0-9+.\-]*://', ''
    $s = $s -replace '^[\\/]+', ''
    $s = ($s -split '[\\/]', 2)[0]
    $s = $s -replace ':\d+$', ''
    $s = $s.TrimEnd('.')
    return $s.Trim()
}

function Test-ServerName {
    # Hostname / FQDN / IPv4 only. Keeps odd characters out of UNC paths and
    # report file names.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -gt 253) { return $false }
    if ($Name -match '\.\.') { return $false }
    return ($Name -match '^[A-Za-z0-9_]([A-Za-z0-9_.\-]*[A-Za-z0-9_])?$')
}

function Get-ServerFolderName {
    # Folder name for one server's reports: the server name itself, made filesystem
    # safe. Lower-cased so OZSSU02 / ozssu02 land in the same folder (Windows paths are
    # case-insensitive anyway); Windows device names (con, nul, com1 ...) get a '_'
    # prefix because a folder with that name cannot be created.
    param([string]$Name)
    $n = ($Name -replace '[^A-Za-z0-9._\-]', '_').ToLowerInvariant().Trim('.')
    if (-not $n) { $n = '_unnamed' }
    if ($n -match '^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$') { $n = '_' + $n }
    return $n
}

function Resolve-ServerInput {
    param([string[]]$Raw)
    $valid   = New-Object System.Collections.Generic.List[string]
    $invalid = New-Object System.Collections.Generic.List[string]
    $notes   = New-Object System.Collections.Generic.List[string]
    $seen    = @{}
    # A pasted UNC / URL is ONE token even when its share or path contains
    # spaces (\\srv\My Share). Whitespace only separates servers when what
    # follows is another UNC/URL start, or when the token is a bare host name.
    $start = '["''<]?(?:[\\/]{2}|[A-Za-z][A-Za-z0-9+.\-]*://)'
    foreach ($line in $Raw) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        foreach ($seg in ($line -split '[,;]')) {
            foreach ($piece in ($seg.Trim() -split "\s+(?=$start)")) {
                if (-not $piece) { continue }
                $toks = if ($piece -match "^$start") { @($piece) } else { @($piece -split '\s+') }
                foreach ($tok in $toks) {
                    if (-not $tok) { continue }
                    $name = ConvertTo-ServerName $tok
                    if (-not (Test-ServerName $name)) { $invalid.Add($tok); continue }
                    $key = $name.ToLowerInvariant()
                    if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $valid.Add($name) }
                    # A space inside a UNC/URL is read as part of the share name. If the
                    # user meant a second server there, say so instead of dropping it silently.
                    if ($piece -match "^$start" -and $tok -match '\S\s+\S') {
                        $notes.Add("'$tok' contains a space: read as ONE server '$name' (the space is part of the share name). Separate servers with commas.")
                    }
                }
            }
        }
    }
    return [PSCustomObject]@{ Valid = $valid.ToArray(); Invalid = $invalid.ToArray(); Notes = $notes.ToArray() }
}

function Read-ServerNames {
    param([bool]$First)
    while ($true) {
        $prompt = if ($First) { 'Input server name (e.g. ozssu02.muv.is.keysight.com)' }
                  else        { 'Input another server name (or press Enter to exit)' }
        $raw = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        if ($raw.Trim() -match '^(q|quit|exit)$') { return @() }
        $parsed = Resolve-ServerInput -Raw @($raw)
        foreach ($bad in $parsed.Invalid) {
            Write-Host "[!] '$bad' is not a valid server name (use a host name, FQDN or IPv4) -- skipped." -ForegroundColor Yellow
        }
        foreach ($note in $parsed.Notes) { Write-Host "[i] $note" -ForegroundColor DarkYellow }
        if ($parsed.Valid.Count -gt 0) { return $parsed.Valid }
    }
}

function Resolve-ServerAddresses {
    param([string]$Name, [int]$TimeoutMs)
    try {
        $ar = [System.Net.Dns]::BeginGetHostAddresses($Name, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            return [PSCustomObject]@{ Ok = $false; Display = ''; Error = "DNS lookup for '$Name' timed out after $TimeoutMs ms" }
        }
        $addrs = @([System.Net.Dns]::EndGetHostAddresses($ar))
        if ($addrs.Count -eq 0) {
            return [PSCustomObject]@{ Ok = $false; Display = ''; Ips = @(); Error = "'$Name' did not resolve to any address" }
        }
        $sorted = @($addrs | Sort-Object { $_.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork })
        $shown  = @($sorted | Select-Object -First 3 | ForEach-Object { $_.IPAddressToString })
        return [PSCustomObject]@{ Ok = $true; Display = ($shown -join ', '); Ips = $sorted; Error = '' }
    } catch {
        $ex = Get-RealException $_
        return [PSCustomObject]@{ Ok = $false; Display = ''; Ips = @(); Error = "Name '$Name' could not be resolved ($($ex.Message))" }
    }
}

function Test-Smb445 {
    # Connects to every resolved address IN PARALLEL (one socket per address
    # family) and succeeds on the first one that answers -- the SMB client does
    # its own address selection, so a stale/unroutable first A record must not
    # make a reachable server look dead.
    param([System.Net.IPAddress[]]$Addresses, [int]$TimeoutMs, [int]$Port = 445)
    $pending = New-Object System.Collections.Generic.List[object]
    $lastErr = ''
    try {
        foreach ($a in @($Addresses | Select-Object -First 16)) {
            try {
                $c = New-Object System.Net.Sockets.TcpClient($a.AddressFamily)
                $pending.Add([PSCustomObject]@{ C = $c; Ar = $c.BeginConnect($a, $Port, $null, $null) })
            } catch {
                $lastErr = (Get-RealException $_).Message
            }
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($pending.Count -gt 0) {
            $left = $TimeoutMs - [int]$sw.ElapsedMilliseconds
            if ($left -le 0) { break }
            $handles = [System.Threading.WaitHandle[]]@($pending | ForEach-Object { $_.Ar.AsyncWaitHandle })
            $i = [System.Threading.WaitHandle]::WaitAny($handles, $left)
            if ($i -eq [System.Threading.WaitHandle]::WaitTimeout) { break }
            $p = $pending[$i]
            try {
                $p.C.EndConnect($p.Ar)
                return [PSCustomObject]@{ Open = $true; Error = '' }
            } catch {
                $lastErr = (Get-RealException $_).Message
                try { $p.C.Close() } catch { }
                $pending.RemoveAt($i)
            }
        }
        if ($pending.Count -eq 0 -and $lastErr) {
            return [PSCustomObject]@{ Open = $false; Error = "TCP/$Port connection failed: $($lastErr.Trim())" }
        }
        if ($pending.Count -eq 0) {
            return [PSCustomObject]@{ Open = $false; Error = 'No usable address to connect to' }
        }
        return [PSCustomObject]@{ Open = $false; Error = "TCP/$Port did not answer within $TimeoutMs ms (host down, wrong name, or firewalled)" }
    } catch {
        $ex = Get-RealException $_
        return [PSCustomObject]@{ Open = $false; Error = "TCP/$Port check failed: $($ex.Message)" }
    } finally {
        foreach ($p in $pending) { try { $p.C.Close() } catch { } }
    }
}

function Get-Win32ErrorText {
    param([int]$Code)
    $known = @{
        5    = 'Access denied -- the share list could not be read with this account'
        53   = 'Network path not found (host unreachable / SMB service not answering)'
        54   = 'Network busy'
        64   = 'The network name is no longer available'
        67   = 'Network name not found'
        1219 = 'Windows already holds a connection to this server under different credentials. Close it (net use \\<server> /delete) and retry'
        1231 = 'Network location unreachable'
        1326 = 'Logon failure (unknown user name or bad password)'
        1722 = 'RPC server unavailable'
        1788 = 'Trust relationship failure'
        2114 = 'The Server (LanmanServer) service is not running on the target'
    }
    if ($known.ContainsKey($Code)) { return "$($known[$Code]) (Win32 error $Code)" }
    try {
        return ((New-Object System.ComponentModel.Win32Exception($Code)).Message + " (Win32 error $Code)")
    } catch {
        return "Win32 error $Code"
    }
}

function Get-PrivilegedGroupNote {
    # Domain Admins (512), Schema Admins (518), Enterprise Admins (519): these
    # carry admin rights on member servers over the network, so a report run
    # as such an account overstates what ordinary staff can reach.
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $hits = New-Object System.Collections.Generic.List[string]
        $sids = New-Object System.Collections.Generic.List[object]
        foreach ($g in $id.Groups) { $sids.Add($g) }
        # A UAC-filtered (non-elevated) token carries these groups as deny-only:
        # WindowsIdentity.Groups omits them, but over SMB they are fully effective.
        foreach ($cl in $id.Claims) {
            if ($cl.Type -like '*denyonlysid') {
                try { $sids.Add((New-Object System.Security.Principal.SecurityIdentifier($cl.Value))) } catch { }
            }
        }
        $seenSid = @{}
        foreach ($g in $sids) {
            if ($g.Value -match '^S-1-5-21-\d+-\d+-\d+-(512|518|519)$' -and -not $seenSid.ContainsKey($g.Value)) {
                $seenSid[$g.Value] = $true
                $n = $g.Value
                try { $n = $g.Translate([System.Security.Principal.NTAccount]).Value } catch { }
                $hits.Add($n)
            }
        }
        if ($hits.Count -gt 0) {
            return ("The scanning account is a member of: {0}. Privileged accounts can read almost every share, so this report OVERSTATES what regular staff can reach. For an 'open to all staff' view, re-run from a standard (non-admin) domain user session." -f ($hits -join ', '))
        }
    } catch { }
    return ''
}

# ---------------------------------------------------------------------------
# Per-share probe (runs inside a RunspacePool worker). Opens the share root
# for LISTING only, then reads the root ACL. Never writes anything.
# A RunspacePool worker does not inherit the caller's functions, so everything
# it needs is declared inside this scriptblock.
# ---------------------------------------------------------------------------
$ShareTestScript = {
    param($Unc, $State, $ItemCap, $SampleCount)

    # Tell the supervisor when THIS share actually started (the pool may queue
    # jobs, so the timeout has to run from start, not from submission).
    $State[$Unc] = [System.Diagnostics.Stopwatch]::GetTimestamp()

    function Get-RealEx {
        param($Err)
        $e = $Err.Exception
        while ($e -and $e.InnerException -and ($e -is [System.Management.Automation.RuntimeException])) { $e = $e.InnerException }
        return $e
    }

    function Get-RightsInfo {
        # $Mask = FileSystemRights as unsigned 32-bit.
        param([int64]$Mask)
        # GenericAll 0x10000000 / FullControl 0x1F01FF
        if (($Mask -band 268435456) -ne 0 -or ($Mask -band 2032127) -eq 2032127) { return @{ Label = 'FullControl'; Rank = 4 } }
        # Modify 0x301BF
        if (($Mask -band 197055) -eq 197055) { return @{ Label = 'Modify'; Rank = 3 } }
        # WriteData 0x2, AppendData 0x4, DeleteSubdirsAndFiles 0x40, Delete 0x10000,
        # ChangePermissions 0x40000, TakeOwnership 0x80000, GenericWrite 0x40000000
        if (($Mask -band (2 + 4 + 64 + 65536 + 262144 + 524288 + 1073741824)) -ne 0) { return @{ Label = 'Write'; Rank = 2 } }
        # ReadData/ListDirectory 0x1, GenericRead 0x80000000
        if (($Mask -band (1 + 2147483648)) -ne 0) { return @{ Label = 'Read'; Rank = 1 } }
        return @{ Label = 'Other'; Rank = 0 }
    }

    function Get-BroadLabel {
        # SID-based (not name-based) so it works on localized servers.
        param([string]$Sid)
        switch -Regex ($Sid) {
            '^S-1-1-0$'                  { return 'Everyone' }
            '^S-1-5-11$'                 { return 'Authenticated Users' }
            '^S-1-5-32-545$'             { return 'BUILTIN\Users' }
            '^S-1-5-2$'                  { return 'NETWORK' }
            '^S-1-5-7$'                  { return 'Anonymous Logon' }
            '^S-1-5-32-546$'             { return 'BUILTIN\Guests' }
            '^S-1-5-21-\d+-\d+-\d+-513$' { return 'Domain Users' }
            '^S-1-5-21-\d+-\d+-\d+-514$' { return 'Domain Guests' }
        }
        return $null
    }

    $nameCache = @{}
    function Get-SidName {
        param($Sid)
        $v = $Sid.Value
        if ($nameCache.ContainsKey($v)) { return $nameCache[$v] }
        # Unresolvable SIDs are usually deleted accounts (or belong to a domain this
        # client cannot resolve) -- say so instead of showing a bare S-1-5-21-... .
        $n = $v + ' (unresolved SID)'
        try { $n = $Sid.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        $nameCache[$v] = $n
        return $n
    }

    $res = [ordered]@{
        Unc = $Unc; Status = 'Error'; Detail = ''; Items = $null; ItemsCapped = $false
        Sample = @(); Owner = ''; BroadAccess = @(); AccessList = @(); BroadWrite = $false
        Exposure = ''; AclNote = ''
    }

    # ---- 1) can the share root be opened and listed? ----
    try {
        $count  = 0
        $sample = New-Object System.Collections.Generic.List[string]
        # Explicit enumerator + Dispose: Windows PowerShell 5.1 does not dispose the
        # enumerator when a foreach is left via 'break', which would leak the
        # server-side directory handle on every share that hits the item cap.
        $en = [System.IO.Directory]::EnumerateFileSystemEntries($Unc).GetEnumerator()
        try {
            while ($en.MoveNext()) {
                $count++
                if ($count -gt $ItemCap) { $res.ItemsCapped = $true; $count = $ItemCap; break }
                if ($sample.Count -lt $SampleCount) { $sample.Add([System.IO.Path]::GetFileName($en.Current)) }
            }
        } finally {
            $en.Dispose()
        }
        $res.Items  = $count
        $res.Sample = $sample.ToArray()
        $res.Status = 'Accessible'
        $res.Detail = 'Share root could be opened and listed'
        # Publish the listing outcome BEFORE the (slower) owner/ACL phase, so a
        # timeout during SID lookups cannot throw away an already-proven open share.
        # '|' is illegal in share names, so this key cannot collide with a UNC.
        $State[$Unc + '|listed'] = @{ Items = $res.Items; Capped = $res.ItemsCapped }
    } catch {
        $ex = Get-RealEx $_
        if (-not $ex) { $ex = $_.Exception }
        $u = [int64]$ex.HResult
        if ($u -lt 0) { $u += 4294967296 }
        $win32 = 0
        if ($u -ge 2147942400 -and $u -le (2147942400 + 65535)) { $win32 = $u - 2147942400 }   # HRESULT_FROM_WIN32
        if ($ex -is [System.UnauthorizedAccessException] -or $win32 -eq 5 -or $win32 -eq 65 -or $win32 -eq 1326) {
            $res.Status = 'Denied'
            $res.Detail = 'Access denied'
        } elseif ($ex -is [System.IO.DirectoryNotFoundException] -or $ex -is [System.IO.FileNotFoundException] -or
                  ($win32 -in 2, 3, 53, 64, 67, 121, 1167, 1222, 1225, 1231, 1722)) {
            $res.Status = 'Unavailable'
            $res.Detail = ([string]$ex.Message).Trim() -replace '\s*[\r\n]+\s*', ' '
        } else {
            $res.Status = 'Error'
            $res.Detail = ([string]$ex.Message).Trim() -replace '\s*[\r\n]+\s*', ' '
        }
    }

    # ---- 2) owner + root ACL exposure (only for shares that opened) ----
    if ($res.Status -eq 'Accessible') {
        try {
            $acl     = Get-Acl -LiteralPath $Unc -ErrorAction Stop
            $sidType = [System.Security.Principal.SecurityIdentifier]
            try { $res.Owner = Get-SidName ($acl.GetOwner($sidType)) } catch { }

            $best = @{}
            $deny = 0
            foreach ($ace in $acl.GetAccessRules($true, $true, $sidType)) {
                if ($ace.AccessControlType -ne 'Allow') { $deny++; continue }
                # InheritOnly (2) entries do not apply to the folder itself.
                if (([int]$ace.PropagationFlags -band 2) -ne 0) { continue }
                $mask = [int64][int]$ace.FileSystemRights
                if ($mask -lt 0) { $mask += 4294967296 }
                $ri = Get-RightsInfo $mask
                if ($ri.Rank -eq 0) { continue }
                $k = $ace.IdentityReference.Value
                if (-not $best.ContainsKey($k) -or $best[$k].Rank -lt $ri.Rank) {
                    $best[$k] = @{ Sid = $ace.IdentityReference; Rank = $ri.Rank; Label = $ri.Label }
                }
            }

            $ordered = @($best.Values | Sort-Object `
                @{ Expression = { if (Get-BroadLabel $_.Sid.Value) { 0 } else { 1 } } }, `
                @{ Expression = { -$_.Rank } })

            $broad = New-Object System.Collections.Generic.List[string]
            $all   = New-Object System.Collections.Generic.List[string]
            $i = 0
            foreach ($b in $ordered) {
                $i++
                $isBroad = [bool](Get-BroadLabel $b.Sid.Value)
                # Only look up (DC round trip) the names that will actually be shown.
                $nm = if ($isBroad -or $i -le 12) { Get-SidName $b.Sid } else { '' }
                if ($isBroad) {
                    $broad.Add(('{0}: {1}' -f $nm, $b.Label))
                    if ($b.Rank -ge 2) { $res.BroadWrite = $true }
                }
                if ($i -le 12) { $all.Add(('{0}: {1}' -f $nm, $b.Label)) }
            }
            if ($ordered.Count -gt 12) { $all.Add(('+{0} more' -f ($ordered.Count - 12))) }

            $res.BroadAccess = $broad.ToArray()
            $res.AccessList  = $all.ToArray()
            if ($broad.Count -gt 0) {
                $res.Exposure = if ($res.BroadWrite) { 'BROAD-WRITE' } else { 'BROAD-READ' }
            } else {
                $res.Exposure = 'LIMITED'
            }
            if ($deny -gt 0) {
                $res.AclNote = ('{0} deny entr{1} on root ACL - review manually' -f $deny, $(if ($deny -eq 1) { 'y' } else { 'ies' }))
            }
        } catch {
            $ex2 = Get-RealEx $_
            $res.Exposure = 'UNKNOWN'
            $res.AclNote  = 'Root ACL not readable: ' + $ex2.Message
        }
    }

    return [PSCustomObject]$res
}

function New-ShareResult {
    # Same shape as the worker's result, for shares the supervisor gives up on.
    param([string]$Unc, [string]$Status, [string]$Detail)
    return [PSCustomObject][ordered]@{
        Unc = $Unc; Status = $Status; Detail = $Detail; Items = $null; ItemsCapped = $false
        Sample = @(); Owner = ''; BroadAccess = @(); AccessList = @(); BroadWrite = $false
        Exposure = ''; AclNote = ''
    }
}

function Invoke-ShareAccessTests {
    <#
      Probes every UNC path in a RunspacePool and returns @{ UNC = result }.
      Each share has a hard timeout measured from when its worker STARTED.
      A timed-out worker is abandoned (BeginStop is non-blocking and a blocked
      SMB call usually ignores it) -- it never blocks the report.
    #>
    param(
        [string[]]$UncPaths,
        [int]$Threads,
        [int]$TimeoutSec,
        [int]$ItemCap,
        [int]$SampleCount,
        [string]$Activity,
        [scriptblock]$Worker = $ShareTestScript
    )

    $results = @{}
    if ($UncPaths.Count -eq 0) { return $results }

    $state   = [hashtable]::Synchronized(@{})
    $poolMax = [math]::Max(1, [math]::Min($Threads, $UncPaths.Count))
    $iss     = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool    = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $poolMax, $iss, $Host)
    $pool.Open()

    $jobs = New-Object System.Collections.Generic.List[object]
    $anyHung = $false
    try {
        foreach ($unc in $UncPaths) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($Worker).AddArgument($unc).AddArgument($state).AddArgument($ItemCap).AddArgument($SampleCount)
            $jobs.Add([PSCustomObject]@{ Unc = $unc; Pipe = $ps; Handle = $ps.BeginInvoke(); Done = $false; TimedOut = $false })
        }

        $timeoutTicks = [int64]$TimeoutSec * [System.Diagnostics.Stopwatch]::Frequency
        $remaining = $jobs.Count
        $total     = $jobs.Count

        while ($remaining -gt 0) {
            $now = [System.Diagnostics.Stopwatch]::GetTimestamp()
            foreach ($j in $jobs) {
                if ($j.Done) { continue }
                if ($j.Handle.IsCompleted) {
                    $r = $null
                    try {
                        $out = $j.Pipe.EndInvoke($j.Handle)
                        if ($out -and $out.Count -gt 0) { $r = $out[0] }
                    } catch {
                        $ex = Get-RealException $_
                        $r = New-ShareResult -Unc $j.Unc -Status 'Error' -Detail ('Probe failed: ' + $ex.Message)
                    }
                    if (-not $r) {
                        $why = 'Probe returned no result'
                        if ($j.Pipe.Streams.Error.Count -gt 0) { $why += ': ' + $j.Pipe.Streams.Error[0].ToString() }
                        $r = New-ShareResult -Unc $j.Unc -Status 'Error' -Detail $why
                    }
                    $results[$j.Unc] = $r
                    $j.Pipe.Dispose()
                    $j.Done = $true
                    $remaining--
                } elseif ($state.ContainsKey($j.Unc) -and (($now - [int64]$state[$j.Unc]) -gt $timeoutTicks)) {
                    try { [void]$j.Pipe.BeginStop($null, $null) } catch { }
                    $t = New-ShareResult -Unc $j.Unc -Status 'Timeout' -Detail "No answer within ${TimeoutSec}s (share target hung, offline or unreachable)"
                    # If the share root was already listed and only the owner/ACL
                    # lookup is slow, it is still a proven OPEN share -- keep that.
                    $lk = $state[$j.Unc + '|listed']
                    if ($lk) {
                        $t.Status = 'Accessible'
                        $t.Detail = 'Share root could be opened and listed'
                        $t.Items = $lk.Items
                        $t.ItemsCapped = $lk.Capped
                        $t.Exposure = 'UNKNOWN'
                        $t.AclNote = "Owner/ACL lookup did not finish within ${TimeoutSec}s"
                    }
                    $results[$j.Unc] = $t
                    $j.Done = $true
                    $j.TimedOut = $true
                    $anyHung = $true
                    $script:AbandonedProbes++
                    $remaining--
                    # BeginStop cannot free a thread blocked in a Win32/SMB call. Give
                    # the pool a replacement slot so queued shares can still start.
                    try { if ($pool.SetMaxRunspaces($pool.GetMaxRunspaces() + 1)) { $poolMax++ } } catch { }
                }
            }

            # Last-resort fallback (only reached if the pool could not be grown):
            # if every pool thread is stuck behind an abandoned probe, queued
            # shares cannot start -- mark them instead of spinning forever.
            if ($remaining -gt 0) {
                $stuck = @($jobs | Where-Object { $_.TimedOut -and -not $_.Handle.IsCompleted }).Count
                if ($stuck -ge $poolMax) {
                    foreach ($j in $jobs) {
                        if (-not $j.Done -and -not $state.ContainsKey($j.Unc)) {
                            $results[$j.Unc] = New-ShareResult -Unc $j.Unc -Status 'NotTested' -Detail 'Not tested: all probe workers were blocked on unresponsive shares'
                            $j.Done = $true
                            $remaining--
                        }
                    }
                }
            }

            $done = $total - $remaining
            $pct  = if ($total -gt 0) { [int](100 * $done / $total) } else { 100 }
            Write-Progress -Activity $Activity -Status "$done / $total shares tested" -PercentComplete $pct
            if ($remaining -gt 0) { Start-Sleep -Milliseconds 100 }
        }
    } finally {
        Write-Progress -Activity $Activity -Completed
        # Unfinished jobs here mean an abort (Ctrl+C) or an abandoned probe: a worker
        # may be stuck in a blocking SMB call and Close() would wait for it. Ask for
        # an async close and move on.
        $unfinished = @($jobs | Where-Object { -not $_.Done }).Count
        if ($anyHung -or $unfinished -gt 0) {
            try { [void]$pool.BeginClose($null, $null) } catch { }
        } else {
            try { $pool.Close(); $pool.Dispose() } catch { }
        }
    }
    return $results
}

# ---------------------------------------------------------------------------
# Report builders
# ---------------------------------------------------------------------------
$ExposureRank  = @{ 'BROAD-WRITE' = 0; 'BROAD-READ' = 1; 'LIMITED' = 2; 'UNKNOWN' = 3; 'DEFAULT' = 4 }
$ExposureColor = @{ 'BROAD-WRITE' = 'Red'; 'BROAD-READ' = 'Yellow'; 'LIMITED' = 'White'; 'UNKNOWN' = 'Gray'; 'DEFAULT' = 'Gray' }

function Add-Line {
    param([System.Collections.Generic.List[object]]$Lines, [string]$Text = '', [string]$Color = '')
    $Lines.Add([PSCustomObject]@{ Text = $Text; Color = $Color })
}

function Format-Leader {
    param([string]$Label, $Value)
    return ('   ' + ($Label + ' ').PadRight(30, '.') + ' ' + $Value)
}

function Get-ItemsText {
    param($Row)
    if ($Row.TopLevelItems -eq '0') { return 'empty' }
    return [string]$Row.TopLevelItems    # '2', '81', '1000+'
}

function Get-ExposureText {
    param($Row)
    switch ($Row.Exposure) {
        'BROAD-WRITE' { return 'BROAD-WRITE (' + $Row.BroadAccess + ')' }
        'BROAD-READ'  { return 'BROAD-READ (' + $Row.BroadAccess + ')' }
        'LIMITED'     { return 'LIMITED (no Everyone / Auth. Users / Domain Users entry on root ACL)' }
        'DEFAULT'     { return 'not rated (Windows default share)' }
        default       { return 'UNKNOWN (' + $(if ($Row.AclNote) { $Row.AclNote } else { 'ACL not evaluated' }) + ')' }
    }
}

function Get-SortedAccessible {
    param($Rows)
    # NB: a 1-element result unrolls to a bare object on return, and a bare
    # PSCustomObject has no .Count in Windows PowerShell 5.1 (the headline count
    # printed blank). EVERY CALLER MUST WRAP THE CALL IN @(...). Do not "fix" this
    # with 'return ,@(...)' as well -- combined with the caller's @() it nests.
    return @($Rows | Where-Object { $_.Status -eq 'Accessible' } | Sort-Object `
        @{ Expression = { if ($_.Kind -eq 'Custom') { 0 } else { 1 } } }, `
        @{ Expression = { $ExposureRank[$_.Exposure] } }, `
        @{ Expression = { $_.Share } })
}

function ConvertTo-PrintableText {
    # Share names / comments / owners come from the remote server: strip control
    # characters (CR/LF would forge extra report lines, ESC reaches the console).
    param($Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value -replace '[\x00-\x1F\x7F-\x9F]+', ' ')
}

function Build-TextReport {
    param($Info, $Rows, [bool]$ShowAllRows)

    $L   = New-Object System.Collections.Generic.List[object]
    $bar = '=' * 76
    $thin = '-' * 76

    $acc    = @(Get-SortedAccessible $Rows)
    $denied = @($Rows | Where-Object { $_.Status -eq 'Denied' })
    $cant   = @($Rows | Where-Object { $CantStatuses -contains $_.Status })
    $notDisk = @($Rows | Where-Object { $_.Status -eq 'NotDisk' })

    Add-Line $L $bar 'Cyan'
    Add-Line $L (" {0}" -f $Info.Title) 'Cyan'
    Add-Line $L $bar 'Cyan'
    Add-Line $L (" Server       : {0}{1}" -f $Info.Server, $(if ($Info.Addresses) { "  ($($Info.Addresses))" } else { '' }))
    Add-Line $L (" Scanned as   : {0}" -f $Info.ScannedAs)
    Add-Line $L (" Scan time    : {0}" -f $Info.ScanTime)
    Add-Line $L " Method       : Read-only. Shares listed with NetShareEnum; each disk share root"
    Add-Line $L "                opened for listing with the account above. Nothing was written."
    if ($Info.Warning) {
        Add-Line $L ''
        Add-Line $L (" [!] NOTE: {0}" -f $Info.Warning) 'Yellow'
    }
    Add-Line $L $thin
    Add-Line $L ' SUMMARY'
    Add-Line $L (Format-Leader 'Shares on server' $Rows.Count)
    $accColor = if ($acc.Count -gt 0 -or $cant.Count -gt 0) { 'Yellow' } else { 'Green' }
    Add-Line $L (Format-Leader 'ACCESSIBLE (open)' ("{0}{1}" -f $acc.Count, $(if ($acc.Count -gt 0) { '   <-- listed below' } else { '' }))) $accColor
    Add-Line $L (Format-Leader 'Access denied' $denied.Count)
    if ($cant.Count -gt 0) {
        Add-Line $L (Format-Leader 'COULD NOT BE TESTED' ("{0}   (offline / timeout / error)" -f $cant.Count)) 'Yellow'
    }
    if ($notDisk.Count -gt 0) {
        Add-Line $L (Format-Leader 'Not folder shares' ("{0}   (IPC / printer)" -f $notDisk.Count))
    }
    Add-Line $L $thin
    Add-Line $L (" ACCESSIBLE SHARES ({0})" -f $acc.Count) 'Cyan'
    Add-Line $L $thin

    if ($acc.Count -eq 0 -and $cant.Count -gt 0) {
        Add-Line $L (" (none) among the {0} share(s) that could be tested -- but {1} share(s) could NOT be" -f ($Rows.Count - $cant.Count - $notDisk.Count), $cant.Count) 'Yellow'
        Add-Line $L ' tested (listed below). This is NOT a clean result.' 'Yellow'
    } elseif ($acc.Count -eq 0) {
        Add-Line $L (" (none) -- no share on this server could be opened by {0}." -f $Info.ScannedAs) 'Green'
    } else {
        $n = 0
        foreach ($r in $acc) {
            $n++
            $tags = ''
            if ($r.Kind -ne 'Custom') { $tags += '  [default/system share]' }
            if ($r.Hidden)            { $tags += '  [hidden: name ends in $]' }
            $color = $ExposureColor[$r.Exposure]
            Add-Line $L ('{0,3}. {1}{2}' -f $n, $r.UNCPath, $tags) 'White'
            # NB: each element is parenthesised -- the comma operator binds tighter than '+'.
            $parts = @(('Exposure: ' + (Get-ExposureText $r)), ('Items: ' + (Get-ItemsText $r)))
            if ($r.Owner) { $parts += ('Owner: ' + $r.Owner) }
            Add-Line $L ('       ' + ($parts -join '  |  ')) $color
            if ($r.Comment)  { Add-Line $L ('       Comment : ' + $r.Comment) 'Gray' }
            if ($r.Sample)   { Add-Line $L ('       Sample  : ' + $r.Sample) 'Gray' }
            if ($r.AclNote -and $r.Exposure -ne 'UNKNOWN') { Add-Line $L ('       Note    : ' + $r.AclNote) 'Gray' }
        }
    }

    # Shares that could not be tested are UNKNOWN (not closed), so they are always
    # listed. -ShowAll additionally lists the denied and non-folder shares.
    $extra = @()
    if ($ShowAllRows) { $extra += @{ Title = 'NOT ACCESSIBLE'; Items = $denied } }
    $extra += @{ Title = 'COULD NOT BE TESTED -- unknown, NOT closed'; Items = $cant }
    if ($ShowAllRows) { $extra += @{ Title = 'NOT FOLDER SHARES'; Items = $notDisk } }
    foreach ($g in $extra) {
        if ($g.Items.Count -eq 0) { continue }
        Add-Line $L $thin
        Add-Line $L (" {0} ({1})" -f $g.Title, $g.Items.Count) 'Cyan'
        Add-Line $L $thin
        foreach ($r in ($g.Items | Sort-Object Share)) {
            Add-Line $L ('   {0}  --  {1}' -f $r.UNCPath, $r.Detail) 'Gray'
        }
    }

    Add-Line $L $thin
    Add-Line $L ' NOTES'
    Add-Line $L '  - "Accessible" = the account above could open and list the share root. It says'
    Add-Line $L '    nothing about other accounts; run as a standard domain user for an "open to'
    Add-Line $L '    all staff" view.'
    Add-Line $L '  - Exposure comes from the root folder NTFS ACL (share-level permissions and deny'
    Add-Line $L '    entries are not evaluated). BROAD-WRITE is a strong indicator, not proof.'
    Add-Line $L '    LIMITED only means no Everyone/Authenticated Users/Domain Users/Users entry --'
    Add-Line $L '    a large group can still be listed; review who is on the ACL (see the .csv/.html).'
    if (@($acc | Where-Object { $_.Exposure -eq 'DEFAULT' }).Count -gt 0) {
        Add-Line $L '  - Default shares are not rated: opening C$/ADMIN$ means this account has admin'
        Add-Line $L '    rights on the server; NETLOGON/SYSVOL/PRINT$ are open to users by design.'
    }
    Add-Line $L '  - "Access denied" = the root folder could not be listed (a traverse-only root reads'
    Add-Line $L '    as denied too). DFS links are not followed; Items counts only what this account'
    Add-Line $L '    can see. Unresolved names are deleted accounts or a domain this PC cannot resolve.'
    Add-Line $L '  - A saved credential or an existing "net use" session to this server can override'
    Add-Line $L '    the "Scanned as" logon above.'
    if (-not $ShowAllRows -and ($denied.Count + $notDisk.Count) -gt 0) {
        Add-Line $L '  - Re-run with -ShowAll to also list the non-accessible shares.'
    }
    Add-Line $L ("  {0} v{1}" -f $ToolName, $ToolVersion) 'DarkGray'
    Add-Line $L $bar 'Cyan'
    return $L
}

function ConvertTo-HtmlText {
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Build-HtmlReport {
    param($Info, $Rows, [bool]$ShowAllRows)

    $acc     = @(Get-SortedAccessible $Rows)
    $denied  = @($Rows | Where-Object { $_.Status -eq 'Denied' })
    $cant    = @($Rows | Where-Object { $CantStatuses -contains $_.Status })
    $notDisk = @($Rows | Where-Object { $_.Status -eq 'NotDisk' })
    $expClass = @{ 'BROAD-WRITE' = 'bw'; 'BROAD-READ' = 'br'; 'LIMITED' = 'lim'; 'UNKNOWN' = 'unk'; 'DEFAULT' = 'unk' }
    $h = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine(('<title>{0} - {1}</title>' -f (& $h $Info.Title), (& $h $Info.Server)))
    [void]$sb.AppendLine(@'
<style>
body{font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:13px;color:#1b2631;margin:20px}
h1{font-size:20px;margin:0 0 10px 0}
h2{font-size:15px;margin:22px 0 6px 0}
table{border-collapse:collapse}
table.meta td{padding:2px 14px 2px 0;vertical-align:top}
table.data{width:100%}
table.data th{background:#2c3e50;color:#fff;text-align:left;padding:6px 8px;border:1px solid #d5d8dc}
table.data td{padding:5px 8px;border:1px solid #d5d8dc;vertical-align:top}
.bw{background:#fadbd8;font-weight:bold}
.br{background:#fcf3cf;font-weight:bold}
.lim{background:#eaf2f8}
.unk{background:#f2f3f4}
.warn{background:#fcf3cf;border:1px solid #f1c40f;padding:8px;margin:10px 0}
.small{color:#566573;font-size:12px}
.mono{font-family:Consolas,monospace}
</style></head><body>
'@)
    [void]$sb.AppendLine(('<h1>{0}</h1>' -f (& $h $Info.Title)))
    [void]$sb.AppendLine('<table class="meta">')
    $addr = if ($Info.Addresses) { ' (' + $Info.Addresses + ')' } else { '' }
    [void]$sb.AppendLine(('<tr><td><b>Server</b></td><td>{0}</td></tr>' -f (& $h ($Info.Server + $addr))))
    [void]$sb.AppendLine(('<tr><td><b>Scanned as</b></td><td>{0}</td></tr>' -f (& $h $Info.ScannedAs)))
    [void]$sb.AppendLine(('<tr><td><b>Scan time</b></td><td>{0}</td></tr>' -f (& $h $Info.ScanTime)))
    [void]$sb.AppendLine('<tr><td><b>Method</b></td><td>Read-only. Shares listed with NetShareEnum; each disk share root opened for listing with the account above. Nothing was written.</td></tr>')
    [void]$sb.AppendLine('</table>')
    if ($Info.Warning) {
        [void]$sb.AppendLine(('<div class="warn"><b>Note:</b> {0}</div>' -f (& $h $Info.Warning)))
    }

    [void]$sb.AppendLine('<h2>Summary</h2><table class="meta">')
    [void]$sb.AppendLine(('<tr><td>Shares on server</td><td><b>{0}</b></td></tr>' -f $Rows.Count))
    [void]$sb.AppendLine(('<tr><td>Accessible (open)</td><td><b>{0}</b></td></tr>' -f $acc.Count))
    [void]$sb.AppendLine(('<tr><td>Access denied</td><td>{0}</td></tr>' -f $denied.Count))
    [void]$sb.AppendLine(('<tr><td>Could not be tested (offline / timeout / error)</td><td>{0}</td></tr>' -f $cant.Count))
    [void]$sb.AppendLine(('<tr><td>Not folder shares (IPC / printer)</td><td>{0}</td></tr>' -f $notDisk.Count))
    [void]$sb.AppendLine('</table>')

    [void]$sb.AppendLine(('<h2>Accessible shares ({0})</h2>' -f $acc.Count))
    if ($acc.Count -eq 0 -and $cant.Count -gt 0) {
        [void]$sb.AppendLine(('<p class="warn"><b>None among the {0} share(s) that could be tested.</b> {1} share(s) could NOT be tested (listed below) - this is NOT a clean result.</p>' -f ($Rows.Count - $cant.Count - $notDisk.Count), $cant.Count))
    } elseif ($acc.Count -eq 0) {
        [void]$sb.AppendLine(('<p>None - no share on this server could be opened by {0}.</p>' -f (& $h $Info.ScannedAs)))
    } else {
        [void]$sb.AppendLine('<table class="data"><tr><th>#</th><th>Share</th><th>Exposure</th><th>Items</th><th>Owner</th><th>Comment</th></tr>')
        $n = 0
        foreach ($r in $acc) {
            $n++
            $kind = ''
            if ($r.Kind -ne 'Custom') { $kind += ' <span class="small">[default/system]</span>' }
            if ($r.Hidden)            { $kind += ' <span class="small">[hidden]</span>' }
            $itemsCell = & $h (Get-ItemsText $r)
            $notes = ''
            if ($r.AclNote) { $notes = '<br><span class="small">' + (& $h $r.AclNote) + '</span>' }
            if ($r.Sample)  { $notes += '<br><span class="small">Sample: ' + (& $h $r.Sample) + '</span>' }
            # Who has broad access goes under the exposure label; the full root-ACL list
            # goes on its own full-width row so the table stays narrow enough for email.
            $broadCell = ''
            if ($r.BroadAccess) { $broadCell = '<br><span class="small">' + (& $h $r.BroadAccess) + '</span>' }
            [void]$sb.AppendLine(('<tr><td>{0}</td><td class="mono">{1}{2}</td><td class="{3}">{4}{5}</td><td style="white-space:nowrap">{6}</td><td>{7}</td><td>{8}</td></tr>' -f `
                $n, (& $h $r.UNCPath), $kind, $expClass[$r.Exposure], (& $h $r.Exposure), $broadCell, $itemsCell, (& $h $r.Owner), ((& $h $r.Comment) + $notes)))
            if ($r.AccessList) {
                [void]$sb.AppendLine(('<tr><td></td><td colspan="5" class="small">Root ACL: {0}</td></tr>' -f (& $h $r.AccessList)))
            }
        }
        [void]$sb.AppendLine('</table>')
    }

    # Shares that could not be tested are unknown (not closed) -- always listed.
    $extra = @()
    if ($ShowAllRows) { $extra += @{ Title = 'Not accessible'; Items = $denied } }
    $extra += @{ Title = 'Could not be tested - unknown, NOT closed'; Items = $cant }
    if ($ShowAllRows) { $extra += @{ Title = 'Not folder shares'; Items = $notDisk } }
    foreach ($g in $extra) {
        if ($g.Items.Count -eq 0) { continue }
        [void]$sb.AppendLine(('<h2>{0} ({1})</h2>' -f $g.Title, $g.Items.Count))
        [void]$sb.AppendLine('<table class="data"><tr><th>Share</th><th>Result</th></tr>')
        foreach ($r in ($g.Items | Sort-Object Share)) {
            [void]$sb.AppendLine(('<tr><td class="mono">{0}</td><td>{1}</td></tr>' -f (& $h $r.UNCPath), (& $h $r.Detail)))
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<h2>Notes</h2><ul class="small">')
    [void]$sb.AppendLine('<li>"Accessible" means the scanning account could open and list the share root. It says nothing about other accounts; run as a standard domain user for an "open to all staff" view.</li>')
    [void]$sb.AppendLine('<li>Exposure comes from the root folder NTFS ACL. Share-level permissions and deny entries are not evaluated, so BROAD-WRITE is a strong indicator, not proof. LIMITED only means there is no Everyone / Authenticated Users / Domain Users / Users entry - a large group can still be listed, so review who is on the ACL.</li>')
    if (@($acc | Where-Object { $_.Exposure -eq 'DEFAULT' }).Count -gt 0) { [void]$sb.AppendLine('<li>Default shares are not rated: opening C$/ADMIN$ means the scanning account has admin rights on the server; NETLOGON/SYSVOL/PRINT$ are open to users by design.</li>') }
    [void]$sb.AppendLine('<li>"Access denied" means the root folder could not be listed (a traverse-only root reads as denied too). DFS links are not followed; Items counts only what this account can see. Unresolved names are deleted accounts or a domain this PC cannot resolve.</li>')
    [void]$sb.AppendLine('<li>A saved credential or an existing "net use" session to this server can override the "Scanned as" logon.</li>')
    if ($cant.Count -gt 0) { [void]$sb.AppendLine('<li>Shares that timed out or were offline are unknown, not closed.</li>') }
    [void]$sb.AppendLine(('<li>Generated by {0} v{1}.</li></ul>' -f (& $h $ToolName), $ToolVersion))
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}

function Build-CsvText {
    param($Rows, [bool]$ShowAllRows)
    # Default: accessible shares + the unknown ones (could not be tested).
    # -ShowAll: every share, accessible first.
    $sel = if ($ShowAllRows) {
        @($Rows | Sort-Object @{ Expression = { if ($_.Status -eq 'Accessible') { 0 } else { 1 } } }, Share)
    } else {
        @(Get-SortedAccessible $Rows) + @($Rows | Where-Object { $CantStatuses -contains $_.Status } | Sort-Object Share)
    }
    $out = foreach ($r in $sel) {
        # Column order: what a recipient needs first, bulky/technical columns last.
        [PSCustomObject][ordered]@{
            UNCPath       = ConvertTo-SafeCellValue $r.UNCPath
            Exposure      = $r.Exposure
            BroadAccess   = ConvertTo-SafeCellValue $r.BroadAccess
            Owner         = ConvertTo-SafeCellValue $r.Owner
            TopLevelItems = $r.TopLevelItems
            Comment       = ConvertTo-SafeCellValue $r.Comment
            Status        = $r.Status
            Kind          = $r.Kind
            Hidden        = $r.Hidden
            AclNote       = ConvertTo-SafeCellValue $r.AclNote
            SampleEntries = ConvertTo-SafeCellValue $r.Sample
            Detail        = ConvertTo-SafeCellValue $r.Detail
            ScannedAs     = $r.ScannedAs
            ScanTime      = $r.ScanTime
            Server        = $r.Server
            Share         = ConvertTo-SafeCellValue $r.Share
            AccessList    = ConvertTo-SafeCellValue $r.AccessList
        }
    }
    if (-not $out) {
        # Keep a header-only file instead of an empty one.
        $out = @([PSCustomObject][ordered]@{
            UNCPath = ''; Exposure = ''; BroadAccess = ''; Owner = ''; TopLevelItems = ''; Comment = ''; Status = ''
            Kind = ''; Hidden = ''; AclNote = ''; SampleEntries = ''; Detail = ''; ScannedAs = ''; ScanTime = ''
            Server = ''; Share = ''; AccessList = ''
        })
        return (($out | ConvertTo-Csv -NoTypeInformation) | Select-Object -First 1) -join "`r`n"
    }
    return (@($out) | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
}

function Write-ReportFile {
    param([string]$Path, [string]$Text)
    # UTF-8 with BOM so Excel/Outlook/Notepad all read non-ASCII share names correctly.
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($true)))
}

# ---------------------------------------------------------------------------
# One server, start to finish
# ---------------------------------------------------------------------------
function Invoke-ServerCheck {
    param([string]$Name, [string]$ReportDir)

    $script:AbandonedProbes = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $summary = [PSCustomObject]@{ Server = $Name; Failed = $false; FailReason = ''; Total = 0; Accessible = 0; NotTested = 0; ReportFailed = $false; Files = @() }

    Write-Host ''
    Write-Host "[*] $Name" -ForegroundColor Cyan

    # 1) DNS
    $dns = Resolve-ServerAddresses -Name $Name -TimeoutMs $PortTimeoutMs
    if (-not $dns.Ok) {
        $summary.Failed = $true; $summary.FailReason = $dns.Error
        Write-Host "    [!] $($dns.Error)" -ForegroundColor Red
        return $summary
    }
    Write-Host "    [*] Resolved: $($dns.Display)"

    # 2) TCP/445
    $tcp = Test-Smb445 -Addresses $dns.Ips -TimeoutMs $PortTimeoutMs
    if (-not $tcp.Open) {
        $summary.Failed = $true; $summary.FailReason = $tcp.Error
        Write-Host "    [!] $($tcp.Error)" -ForegroundColor Red
        return $summary
    }
    Write-Host '    [*] TCP/445 reachable -- listing shares...'

    # 3) NetShareEnum
    $enum = [SmbOpenShare.NetApi]::EnumerateShares($Name)
    if ($enum.ErrorCode -ne 0) {
        $summary.Failed = $true
        $summary.FailReason = 'Share enumeration failed: ' + (Get-Win32ErrorText $enum.ErrorCode)
        Write-Host "    [!] $($summary.FailReason)" -ForegroundColor Red
        return $summary
    }
    $shares = @($enum.Shares)
    Write-Host ("    [*] {0} share(s) found" -f $shares.Count)

    $scannedAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $scanTime  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # 4) classify
    $classified = New-Object System.Collections.Generic.List[object]
    $typeNames = @{ 0 = 'disk'; 1 = 'print'; 2 = 'device'; 3 = 'ipc' }
    foreach ($e in $shares) {
        # Low byte = share type (0 disk, 1 print, 2 device, 3 ipc). Everything above it is
        # flag bits (SPECIAL, TEMPORARY, CLUSTER_FS/SOFS/DFS, ...) and must not leak in --
        # otherwise a clustered disk share would be classed 'unknown(n)' and never probed.
        $raw     = [int]([int64]$e.Type -band 255)
        $special = (([int64]$e.Type -band 2147483648) -ne 0)
        $tn      = if ($typeNames.ContainsKey($raw)) { $typeNames[$raw] } else { "unknown($raw)" }
        $classified.Add([PSCustomObject]@{
            Name    = [string]$e.Name
            Remark  = [string]$e.Remark
            TypeName = $tn
            Unc     = "\\$Name\$($e.Name)"
            Kind    = $(if ($special -or ([string]$e.Name -match $DefaultShareRegex)) { 'Default/System' } else { 'Custom' })
            Hidden  = ([string]$e.Name).EndsWith('$')
        })
    }

    # 5) probe the disk shares
    $disk = @($classified | Where-Object { $_.TypeName -eq 'disk' })
    $probe = @{}
    if ($disk.Count -gt 0) {
        Write-Host ("    [*] Testing {0} disk share(s): {1} parallel, {2}s timeout each (read-only)..." -f $disk.Count, [math]::Min($ShareThreads, $disk.Count), $ShareTimeoutSec)
        $probe = Invoke-ShareAccessTests -UncPaths @($disk | ForEach-Object { $_.Unc }) -Threads $ShareThreads `
            -TimeoutSec $ShareTimeoutSec -ItemCap $MaxItemsCounted -SampleCount $SampleCount -Activity "Testing shares on $Name"
    }

    # 6) assemble rows
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $classified) {
        $p = $null
        if ($c.TypeName -eq 'disk' -and $probe.ContainsKey($c.Unc)) { $p = $probe[$c.Unc] }
        $status = 'NotDisk'; $detail = "Not a folder share ($($c.TypeName))"
        $exposure = ''; $broad = ''; $acl = ''; $owner = ''; $items = ''; $sample = ''; $aclNote = ''
        if ($c.TypeName -eq 'disk') {
            if ($p) {
                $status = $p.Status; $detail = $p.Detail
                $exposure = $p.Exposure; $broad = ($p.BroadAccess -join '; '); $acl = ($p.AccessList -join '; ')
                $owner = $p.Owner; $aclNote = $p.AclNote
                if ($null -ne $p.Items) { $items = [string]$p.Items; if ($p.ItemsCapped) { $items += '+' } }
                $sample = ($p.Sample -join ', ')
            } else {
                $status = 'NotTested'; $detail = 'No probe result'
            }
            # Windows default shares (C$, ADMIN$, NETLOGON, ...) have a Windows-defined
            # share-level ACL, so the root NTFS ACL says nothing useful about who can
            # reach them -- don't rate them. Being able to open one mostly shows the
            # scanning account's own privilege level.
            if ($status -eq 'Accessible' -and $c.Kind -ne 'Custom') { $exposure = 'DEFAULT'; $broad = '' }
        }
        # Everything the remote server supplied is stripped of control characters for
        # display/report purposes. (The raw UNC was already used for probing above.)
        $rows.Add([PSCustomObject]@{
            Server = $Name; Share = (ConvertTo-PrintableText $c.Name); UNCPath = (ConvertTo-PrintableText $c.Unc)
            ShareType = $c.TypeName; Kind = $c.Kind; Hidden = $c.Hidden
            Comment = (ConvertTo-PrintableText $c.Remark); Status = $status; Detail = (ConvertTo-PrintableText $detail)
            Exposure = $exposure; BroadAccess = (ConvertTo-PrintableText $broad)
            AccessList = (ConvertTo-PrintableText $acl); Owner = (ConvertTo-PrintableText $owner); TopLevelItems = $items
            Sample = (ConvertTo-PrintableText $sample); AclNote = (ConvertTo-PrintableText $aclNote)
            ScannedAs = $scannedAs; ScanTime = $scanTime
        })
    }
    $rowsArr = $rows.ToArray()

    # Evidence-based admin warning: if C$ / ADMIN$ / another drive-letter share could be
    # opened, the scanning account has administrative rights on THIS server, so every
    # share below is readable to an admin and does not show what ordinary staff reach.
    $warning = $script:PrivilegedNote
    $adminOpen = @($rowsArr | Where-Object { $_.Status -eq 'Accessible' -and $_.Share -match '^(ADMIN\$|[A-Za-z]\$)$' })
    if ($adminOpen.Count -gt 0) {
        $w = ('The scanning account has ADMINISTRATIVE access to this server ({0} could be opened). Every share below is readable to an admin, so this list does NOT show what ordinary staff can reach. Re-run as a standard (non-admin) user.' -f (($adminOpen | ForEach-Object { $_.Share }) -join ', '))
        $warning = if ($warning) { "$warning $w" } else { $w }
    }

    $info = [PSCustomObject]@{
        Title = 'SMB OPEN-SHARE REPORT'; Server = $Name; Addresses = $dns.Display
        ScannedAs = $scannedAs; ScanTime = $scanTime; Warning = $warning
    }

    # 7) terminal report (accessible only unless -ShowAll)
    $lines = Build-TextReport -Info $info -Rows $rowsArr -ShowAllRows ([bool]$ShowAll)
    Write-Host ''
    foreach ($ln in $lines) {
        if ($ln.Color) { Write-Host $ln.Text -ForegroundColor $ln.Color } else { Write-Host $ln.Text }
    }

    $summary.Total      = $rowsArr.Count
    $summary.Accessible = @($rowsArr | Where-Object { $_.Status -eq 'Accessible' }).Count
    $summary.NotTested  = @($rowsArr | Where-Object { $CantStatuses -contains $_.Status }).Count

    # 8) files
    if (-not $NoReport) {
        # One folder per server: <ReportDir>\<server>\OpenShares_<server>_<timestamp>.{txt,html,csv}
        # The server name stays in the file names too, so a file that gets attached to an
        # email or moved elsewhere still says which server it is about.
        $folderName = Get-ServerFolderName $Name
        $serverDir  = Join-Path $ReportDir $folderName
        $stem = 'OpenShares_{0}_{1}' -f $folderName, (Get-Date -Format 'yyyyMMdd_HHmmss')
        $written = New-Object System.Collections.Generic.List[string]
        try {
            if (-not (Test-Path -LiteralPath $serverDir -PathType Container)) { [void](New-Item -ItemType Directory -Path $serverDir -Force) }
            $txtPath  = Join-Path $serverDir ($stem + '.txt')
            $htmlPath = Join-Path $serverDir ($stem + '.html')
            $csvPath  = Join-Path $serverDir ($stem + '.csv')
            Write-ReportFile -Path $txtPath  -Text ((($lines | ForEach-Object { $_.Text }) -join "`r`n") + "`r`n")
            $written.Add($txtPath)
            Write-ReportFile -Path $htmlPath -Text (Build-HtmlReport -Info $info -Rows $rowsArr -ShowAllRows ([bool]$ShowAll))
            $written.Add($htmlPath)
            Write-ReportFile -Path $csvPath  -Text ((Build-CsvText -Rows $rowsArr -ShowAllRows ([bool]$ShowAll)) + "`r`n")
            $written.Add($csvPath)
        } catch {
            $summary.ReportFailed = $true
            Write-Host "    [!] Could not write report files to '$serverDir': $((Get-RealException $_).Message)" -ForegroundColor Red
        }
        $summary.Files = $written.ToArray()
        if ($written.Count -gt 0) {
            Write-Host ''
            Write-Host "[*] Report folder: $serverDir" -ForegroundColor Green
            Write-Host '    Files (attach / paste into email):' -ForegroundColor Green
            foreach ($f in $written) { Write-Host "      $(Split-Path -Leaf $f)" -ForegroundColor Green }
        }
    }

    $sw.Stop()
    $doneColor = if ($summary.NotTested -gt 0) { 'Yellow' } else { 'Green' }
    $notTestedText = if ($summary.NotTested -gt 0) { ", $($summary.NotTested) NOT tested" } else { '' }
    Write-Host ("[*] {0}: done in {1:N1}s -- {2} of {3} share(s) accessible{4}." -f $Name, $sw.Elapsed.TotalSeconds, $summary.Accessible, $summary.Total, $notTestedText) -ForegroundColor $doneColor
    if ($script:AbandonedProbes -gt 0) {
        Write-Host ("[!] {0} share probe(s) hung and were abandoned; a window started with 'powershell -File' may take up to ~1 minute to close." -f $script:AbandonedProbes) -ForegroundColor Yellow
    }
    return $summary
}

# ===========================================================================
# MAIN
# ===========================================================================

# Dot-sourcing (. .\SMB_oneoff_sweep.ps1) only defines the functions --
# handy for testing them in isolation.
if ($MyInvocation.InvocationName -eq '.') { return }

Write-Host "$ToolName v$ToolVersion  --  read-only; use only on servers you are authorized to assess" -ForegroundColor Cyan

# -Server swallows every leftover argument (so 'script.ps1 host1 host2' works). That
# would also swallow a typo'd parameter (-Timeout 30 -> a host called '30'), so any
# leftover token that looks like a parameter is fatal, before anything is scanned.
$unknownParams = @($Server | Where-Object { $_ -match '^-' })
if ($unknownParams.Count -gt 0) {
    Write-Host "[!] Unknown parameter(s): $($unknownParams -join ', ')" -ForegroundColor Red
    Write-Host '    Run Get-Help .\SMB_oneoff_sweep.ps1 -Detailed for the parameter list.' -ForegroundColor Red
    exit 1
}

$script:PrivilegedNote = Get-PrivilegedGroupNote
if ($script:PrivilegedNote) {
    Write-Host "[!] $($script:PrivilegedNote)" -ForegroundColor Yellow
}

$reportDir = ''
if (-not $NoReport) {
    # Validate/create the report folder UP FRONT so a bad -OutDir fails in one clear
    # line before a (possibly long) scan, not after it.
    try {
        # Default root: a 'Reports' folder next to the script (falls back to the current
        # directory if the script path is unknown, e.g. pasted into a console).
        $reportDir = if ($OutDir) { $OutDir }
                     elseif ($PSScriptRoot) { Join-Path $PSScriptRoot 'Reports' }
                     else { (Get-Location).ProviderPath }
        $reportDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($reportDir)
        if (-not (Test-Path -LiteralPath $reportDir -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $reportDir -Force)
        }
        if (-not (Test-Path -LiteralPath $reportDir -PathType Container)) {
            throw "'$reportDir' exists but is not a folder"
        }
        # Prove the folder is writable now, not after the scan (local file only).
        $writeProbe = Join-Path $reportDir ('.w_' + [guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::WriteAllText($writeProbe, '')
        Remove-Item -LiteralPath $writeProbe -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] Cannot use report folder '$reportDir': $((Get-RealException $_).Message)" -ForegroundColor Red
        Write-Host '    Fix -OutDir, or use -NoReport to skip writing report files.' -ForegroundColor Red
        exit 1
    }
}

# Collect non-interactive input (-Server / -ServerFile).
$queue = New-Object System.Collections.Generic.List[string]
$rawInputs = New-Object System.Collections.Generic.List[string]
if ($Server) { foreach ($s in $Server) { $rawInputs.Add($s) } }
if ($ServerFile) {
    if (-not (Test-Path -LiteralPath $ServerFile -PathType Leaf)) {
        Write-Host "[!] -ServerFile '$ServerFile' not found." -ForegroundColor Red
        exit 1
    }
    $fileEntries = 0
    foreach ($ln in (Get-Content -LiteralPath $ServerFile)) {
        $clean = ($ln -replace '#.*$', '').Trim()
        if ($clean) { $rawInputs.Add($clean); $fileEntries++ }
    }
    if ($fileEntries -eq 0 -and -not $Server) {
        Write-Host "[!] -ServerFile '$ServerFile' contains no server names (blank / comment-only)." -ForegroundColor Red
        exit 1
    }
}
$interactive = ($rawInputs.Count -eq 0)
if (-not $interactive) {
    $parsed = Resolve-ServerInput -Raw $rawInputs.ToArray()
    foreach ($bad in $parsed.Invalid) {
        Write-Host "[!] '$bad' is not a valid server name -- skipped." -ForegroundColor Yellow
    }
    foreach ($note in $parsed.Notes) { Write-Host "[i] $note" -ForegroundColor DarkYellow }
    foreach ($v in $parsed.Valid) { $queue.Add($v) }
    if ($queue.Count -eq 0) {
        Write-Host '[!] No valid server name supplied.' -ForegroundColor Red
        exit 1
    }
}

$summaries = New-Object System.Collections.Generic.List[object]
$first = $true
while ($true) {
    $names = if ($interactive) { @(Read-ServerNames -First $first) } else { $queue.ToArray() }
    if ($names.Count -eq 0) {
        if ($first) { Write-Host '[!] No server name entered.' -ForegroundColor Yellow }
        break
    }
    foreach ($n in $names) {
        $summaries.Add((Invoke-ServerCheck -Name $n -ReportDir $reportDir))
    }
    $first = $false
    if (-not $interactive) { break }
    Write-Host ''
}

# Recap when more than one server was checked.
if ($summaries.Count -gt 1) {
    Write-Host ''
    Write-Host ('=' * 76) -ForegroundColor Cyan
    Write-Host ' OVERALL SUMMARY' -ForegroundColor Cyan
    Write-Host ('=' * 76) -ForegroundColor Cyan
    foreach ($s in $summaries) {
        if ($s.Failed) {
            Write-Host (' {0}  FAILED: {1}' -f $s.Server.PadRight(44), $s.FailReason) -ForegroundColor Red
        } else {
            $c = if ($s.Accessible -gt 0 -or $s.NotTested -gt 0) { 'Yellow' } else { 'Green' }
            $nt = if ($s.NotTested -gt 0) { ", $($s.NotTested) NOT tested" } else { '' }
            Write-Host (' {0}  {1} accessible of {2} share(s){3}' -f $s.Server.PadRight(44), $s.Accessible, $s.Total, $nt) -ForegroundColor $c
        }
    }
}

# Exit codes: 0 = finished, 1 = a server could not be checked, 2 = report files not written.
$anyFailed       = @($summaries | Where-Object { $_.Failed }).Count -gt 0
$anyReportFailed = @($summaries | Where-Object { $_.ReportFailed }).Count -gt 0
exit $(if ($anyFailed) { 1 } elseif ($anyReportFailed) { 2 } else { 0 })
