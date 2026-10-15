# smb_share_sweep.ps1

Subnet-wide SMB share discovery. In spirit (two-phase discovery-then-assess,
live progress bars, one timestamped `.xlsx` at the end) but written in
**PowerShell, not Python** — on purpose, see below. Single script file —
port sweep, share enumeration, and `.xlsx` are all in it.

## What it finds

For every host with 445/tcp open, every SMB share NetShareEnum returns,
bucketed into:

- **[FOUND] Readable - Custom Share** — a non-default share the scanning
  account can list. The primary finding this tool exists to surface; review
  contents for sensitive data.
- **[ADMIN] Readable - Default/System Share** — `ADMIN$`/`C$`/etc. are
  readable, meaning the scanning account has local-administrator-equivalent
  access to that host. Expected on some hosts (e.g. the account's own
  workstation), still worth confirming is intended everywhere else it shows up.
- **[-] Not Readable** — share exists but `Get-ChildItem` was denied or
  errored (ACL, disabled share, etc.).

Plus, per host: best-effort reverse-DNS hostname, whether `NetShareEnum`
itself succeeded (and why not, when it didn't — access denied / logon
failure / trust relationship failure / unreachable), share count, and
per-host scan time.

## Why PowerShell, not Python/impacket

This started as a question: Snaffler (also PowerShell, run from a Windows
box) never needs `-d`/credentials, so why does the impacket-based sibling
tooling? Because the execution models are fundamentally different:

- **Snaffler / this script** run inside your own logon session and ride
  Windows' integrated auth (SSPI/Kerberos) for every `NetShareEnum` call —
  pass-through, no credential handling anywhere in the script.
- **impacket-based tooling** builds the SMB session itself, outside the
  Windows security stack, so it has no access to your Kerberos TGT or logon
  session and must be handed an explicit username/password/hash/domain.

Running this from a domain-joined box as an account that already has the
network access you want to sweep with is strictly better here: nothing to
embed or type into a script, nothing that can end up in shell history or
logs, and it rides whatever Kerberos delegation the account already has —
including trust relationships that would be painful to replicate with
explicit NTLM creds. The cost is PowerShell 5.1's lack of
`ForEach-Object -Parallel` (that needs PS7+), so concurrency here uses
classic runspace pools instead — the same technique PowerView uses, just
more verbose to set up.

**This is also why the script never asks for credentials and never will** —
see "Why not a `-Credential` parameter" below.

## Why not a `-Credential` parameter

An earlier draft of a similar script authenticated explicitly per host via
`net use \\target\IPC$ /user:... password...`, built as a `cmd /c` string
with the password interpolated directly into it. That pattern has two real
problems worth calling out, since it's a natural-looking way to add
credentialed scanning to a tool like this:

1. **Command injection.** Any of `$Target`/`$Domain`/`$Username`/`$Password`
   containing a `"`, `` ` ``, `&`, or `|` breaks out of the `cmd /c` string.
   An input file or a typo'd password is enough.
2. **Credential exposure.** The password sits in plaintext on a process
   command line for the life of that `net use` call — visible to anything
   that can read process lists on the box this runs from (WMI, Process
   Explorer, 4688 command-line auditing), and it lands in PowerShell's own
   command history.

There's a third, broader concern specific to *this* tool's job: sweeping an
entire environment with one set of real domain credentials means offering
that account's NTLM/Kerberos handshake to **every host in scope**, including
any host that's already compromised or spoofed — a captured handshake can be
relayed. The current-user/no-explicit-credential model sidesteps all three
problems by construction rather than by careful escaping, which is why it's
the design here rather than a `-Credential` parameter with `PSCredential`
and `New-SmbMapping`.

## Concurrency model

Two independent levels of parallelism, both running by default — this is
not a sequential, one-host-at-a-time script:

- **Phase 1 (port sweep):** `-Threads` runspaces run concurrently, each
  working through batches of `-BatchSize` IPs. *Within* a batch, every IP's
  connect attempt is fired off asynchronously (non-blocking `BeginConnect`)
  and all of them are waited on together — so the actual number of
  in-flight TCP connection attempts at any instant is roughly
  `Threads × BatchSize` (4,000 at the defaults: 20 × 200).
- **Phase 2 (share enum):** `-ShareThreads` runspaces run concurrently
  (50 by default), each working through a small batch of hosts one at a
  time within that thread — so up to 50 hosts are being enumerated
  simultaneously at the default setting.

## Scope

```powershell
$DefaultSubnets = @(
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "0.121.0.0/16",
    "7.0.0.0/16",
    "8.16.0.0/12",
    "9.0.0.0/8"
)
```

Edit `$DefaultSubnets` in the script, or pass `-Subnets` to override for a
single run — same convention as the sibling scripts' `SUBNETS` list.

## Requirements

- Windows PowerShell 5.1 (confirmed working; no PS7-only syntax is used)
- [`ImportExcel`](https://github.com/dfinke/ImportExcel) module:
  ```powershell
  Install-Module ImportExcel -Scope CurrentUser
  ```
- No `masscan` dependency — this is pure-PowerShell TCP connect scanning for
  Phase 1 (see "Known limitations" for what that costs you at scale).
- No credentials, no elevated privileges beyond whatever the current logon
  session already has.

## Usage

```powershell
.\smb_share_sweep.ps1 -Subnets '192.168.5.0/24' -Threads 10 -BatchSize 100 -ShareThreads 20
```

**Always test on a single `/24` first** to calibrate timing before pointing
this at anything bigger — see "Known limitations."

| Parameter | Default | Purpose |
|---|---|---|
| `-Subnets` | built-in list | Override scope for this run |
| `-Threads` | `20` | Concurrent runspaces for the port-445 sweep |
| `-BatchSize` | `200` | IPs per batch in the port sweep (`Threads * BatchSize` ≈ sockets in flight) |
| `-PortTimeoutMs` | `1000` | How long a port-sweep batch waits for connects to resolve |
| `-ShareThreads` | `50` | Concurrent runspaces for share enumeration |
| `-HostnameTimeoutMs` | `1500` | Per-host reverse-DNS timeout (real async cancellation) |
| `-MaxAddressesWithoutForce` | `20000000` | Refuse to start a scan bigger than this without `-Force`. Set comfortably above the full built-in `$DefaultSubnets` list (~18.15M) so the default scope always runs unattended — it only kicks in for a scope blown up well past that by accident. |
| `-Force` | off | Bypass the size guard |
| `-OutPath` | `SMB-SWEEP-<timestamp>.xlsx` | Output workbook path. A companion `.csv` with the same base name (Results sheet rows) is written alongside it automatically. |
| `-HostsCsv` | — | Skip Phase 1, reuse a `Subnet,Host` CSV from a previous run |

Re-run just Phase 2 against a saved host list (e.g. to raise `-ShareThreads`
without re-sweeping ports):

```powershell
.\smb_share_sweep.ps1 -HostsCsv .\phase1_hosts_20261001_110607.csv -ShareThreads 75
```

Scan something bigger than the default guard allows:

```powershell
.\smb_share_sweep.ps1 -Subnets '10.0.0.0/8' -Force
```

## Output

- `phase1_hosts_<timestamp>.csv` — raw Phase 1 host list, saved before Phase
  2 starts so a crash there doesn't lose the port-sweep work
- `SMB-SWEEP-<timestamp>.xlsx` — four sheets:
  - **Overview** — scan date/subnet count, a category legend explaining
    Custom vs. Default/System shares, a Scan Summary with counts/percentages
    per category, a **Top 20 Hosts** table (ranked by readable custom
    shares first, since that's the "anyone can read this" signal — a
    readable `ADMIN$`/`C$` mostly just reflects the scanning account's own
    admin rights, not public exposure), a **Subnet Breakdown** (Total
    Shares / Readable Custom / Readable Default-Admin per subnet, sorted by
    exposure), and a grand **Total Readable Shares (All)** at the bottom.
    Deliberately does *not* include scan tuning parameters (thread counts,
    batch size, timeouts) — those were cut as noise that didn't belong in a
    findings report.
  - **Results** — one row per share found (Subnet, Host, Hostname, Share,
    UNCPath, ShareType, IsDefault, Comment, Readable, Category, Error),
    color-coded by category, frozen header + autofilter. `UNCPath` is the
    ready-to-paste `\\host\share` form (e.g. `\\10.7.1.6\Public`).
  - **Hosts** — one row per host contacted (auth success/failure, share
    count, scan time), failed-auth rows highlighted
  - **Detailed Stats** — formula-driven per-subnet counts (`COUNTIF`/
    `COUNTIFS` against the Results/Hosts sheets, not precomputed values)
- `SMB-SWEEP-<timestamp>.csv` — same rows/columns as the Results sheet, same
  "one wide CSV + one .xlsx per run" convention as `sslspray.py`/
  `telnet_spray.py`

## Security practices applied

- **No write/delete, ever.** An earlier revision had a write-probe (create +
  delete a temp file per writable share); it was removed. This script only
  confirms a share is *readable*.
- **No credentials collected, stored, or transmitted.** See "Why not a
  `-Credential` parameter" above.
- **CSV/Excel formula injection (CWE-1236).** `Share` name and `Comment` come
  from `NetShareEnum` on hosts across the whole scope, so on a compromised or
  untrusted box an attacker fully controls those strings. Any value starting
  with `=`, `+`, `-`, `@`, tab, or CR gets a leading quote forced on, matching
  the fix already applied in `sslspray.py`/`telnet_spray.py`.
- **Scope-size guard.** A scan over `-MaxAddressesWithoutForce` addresses
  (default 20,000,000 — above the full built-in `$DefaultSubnets` list) is
  refused unless `-Force` is passed, so a scope blown up well past your
  actual environment can't silently eat unattended runtime.
- **CIDR validation.** A malformed `-Subnets` entry fails with a clear
  message naming the bad entry, instead of a raw .NET exception partway
  through a scan.
- **Guaranteed native-buffer cleanup.** `NetApiBufferFree` runs in a
  `finally` block so a marshalling exception mid-enumeration can't leak the
  `NetShareEnum` buffer.

## Known limitations

- **Scan speed.** This is TCP connect scanning, not raw SYN packets (no
  masscan dependency) — far slower than the Python siblings on huge ranges.
  `10.0.0.0/8` is ~16.7M addresses; budget hours, not minutes, for the full
  default scope. Rough formula for Phase 1:
  `ceil(TotalAddresses / (Threads × BatchSize)) × (PortTimeoutMs / 1000)` —
  at the defaults (`Threads=20`, `BatchSize=200`, `PortTimeoutMs=1000`) the
  full built-in subnet list (~18.15M addresses) works out to roughly
  75–90 minutes for Phase 1 alone, plus a measured ~8 minutes of
  single-threaded IP-list construction *before* Phase 1 even starts
  (`Get-CidrBatches` has to format every address as a string up front).
  Phase 2's duration depends entirely on how many hosts actually answer on
  445/tcp, which can't be predicted ahead of time. Test on a `/24` first and
  extrapolate from the observed timing, not just this formula — real network
  behavior (dropped vs. refused connections, latency) affects it more than
  any of these numbers can predict.
- **Splitting the subnet list into smaller chunks does not make this
  faster.** Every batch from every configured subnet already goes into one
  shared runspace-pool queue processed by up to `-Threads` concurrent
  workers — the pool doesn't scan subnet-by-subnet, so breaking `-Subnets`
  into several separate invocations does the same total work with extra
  per-invocation overhead (new runspace pool, separate reports) instead of
  less. The levers that actually change wall-clock time on one machine are
  `-Threads`, `-BatchSize`, and `-PortTimeoutMs` (bounded by local ephemeral
  ports and CPU, not by subnet boundaries); genuine speedup beyond that
  would mean running separate instances from *different machines* against
  disjoint parts of the scope at the same time.
- **A hung share can't be forcibly cut short.** This was tested, not
  assumed: wrapping the per-share `Get-ChildItem` probe in a background
  `Task` and calling `.Wait(timeoutMs)` throws immediately (a .NET
  `Task.Run` thread has no PowerShell runspace to execute cmdlets in), and
  the alternative — a nested `[PowerShell]` pipeline stopped via `.Stop()`
  after a timeout — doesn't actually cut anything short either: `.Stop()`
  just blocks until the underlying blocked Win32 file-I/O call gives up on
  its own OS-level timeout (~20s+ against an unreachable path in testing),
  which is the same wait either way. There's no cheap, reliable way to
  preempt a blocked synchronous SMB read from pure PowerShell. Impact is
  bounded rather than eliminated: hosts are processed in small batches per
  runspace-pool thread (a handful of hosts per batch at typical
  `-ShareThreads` settings), so one hung share only delays the other hosts
  queued in that same batch, not the whole sweep.
- **Reverse DNS is best-effort.** Uses the real async `Dns.BeginGetHostEntry`
  API, so the timeout is genuine cancellation (unlike the share-read case
  above) — a slow/absent PTR record just leaves `Hostname` blank rather than
  stalling the host.
- **The `CustomReadable` number on Detailed Stats can look wrong the instant
  the file is generated, but self-corrects the moment you open it.** Tested
  and confirmed: ImportExcel/EPPlus's own bundled formula-calculation engine
  (used to pre-populate cached values when the script builds the file) can
  miscount this one `COUNTIFS` call — a text-equality criteria pair combined
  with two boolean criteria pairs in a single `COUNTIFS`. The formula text
  itself is standard, valid Excel syntax; this is purely an EPPlus
  calculation-engine limitation, not a formula bug, and no amount of
  criteria reordering reliably works around it (tried — still wrong on a
  richer test dataset). It's harmless in practice: the generated workbook
  has `fullCalcOnLoad="1"` set (verified in the file's XML), which forces
  Excel/LibreOffice to recompute every formula with their own correct engine
  the instant the file opens, overwriting whatever EPPlus cached. Every
  other sheet/value is correct from the moment the script finishes — this
  affects only that one cached cell, only before first open.

--------------------------------------------------------------------------------------------

  # SMB_oneoff_sweep.ps1

Find out which SMB shares on a server are actually **open** to the account you run it as, without clicking through every folder in Explorer. Lists the accessible shares, rates how widely each one is exposed, and writes a report you can paste or attach into an email.

Read-only. No credentials, no modules, no admin rights. Uses your current Windows logon.

> Use only on servers you are authorized to assess.

## Requirements

- Windows with PowerShell 5.1 or later
- Network access to the server on TCP 445

## Usage

```powershell
.\SMB_oneoff_sweep.ps1
```

It prompts for a server name. Paste a hostname, an FQDN, an IPv4 address, or a `\\server\share` path (the share part is ignored). Separate several servers with commas.

```powershell
.\SMB_oneoff_sweep.ps1 fileserver01.corp.example.com
.\SMB_oneoff_sweep.ps1 server1, server2, server3
.\SMB_oneoff_sweep.ps1 -ServerFile .\servers.txt        # one server per line, # for comments
.\SMB_oneoff_sweep.ps1 fileserver01 -ShowAll            # also list denied shares
.\SMB_oneoff_sweep.ps1 fileserver01 -OutDir D:\audit    # change the reports folder
```

If scripts are blocked: `powershell -ExecutionPolicy Bypass -File .\SMB_oneoff_sweep.ps1`

### Options

| Option | Default | Purpose |
|---|---|---|
| `-Server` | prompt | One or more servers |
| `-ServerFile` | | Text file of servers |
| `-OutDir` | `Reports` next to the script | Root folder for reports |
| `-ShowAll` | off | Also list denied and non-folder shares |
| `-NoReport` | off | Terminal output only |
| `-SampleCount` | `0` | Include the first N entry names per open share (off by default; names can be sensitive) |
| `-ShareTimeoutSec` | `20` | Per-share timeout |
| `-ShareThreads` | `16` | Shares tested in parallel |

Exit codes: `0` done, `1` a server could not be checked or bad input, `2` scan finished but reports could not be written.

## Example output

```
 ACCESSIBLE SHARES (3)
  1. \\fileserver01.corp.example.com\DataStorage
       Exposure: BROAD-WRITE (Everyone: FullControl)  |  Items: 2  |  Owner: CORP\jsmith
  2. \\fileserver01.corp.example.com\Public
       Exposure: BROAD-READ (NT AUTHORITY\Authenticated Users: Read)  |  Items: 81  |  Owner: CORP\jsmith
```

## Reports

Each server gets its own folder. Files are timestamped, so re-scans never overwrite earlier results.

```
Reports\
  fileserver01.corp.example.com\
    OpenShares_fileserver01.corp.example.com_20261015_141200.txt    paste into an email
    OpenShares_fileserver01.corp.example.com_20261015_141200.html   paste into Outlook as a table
    OpenShares_fileserver01.corp.example.com_20261015_141200.csv    attach / open in Excel
```

## How it works

**Readable is tested for real.** For every share the script opens the root folder and lists it. A share is only reported as accessible if that listing succeeded, so "accessible" means the account running the script could actually read it.

**Writable is inferred, not tested.** The script never writes anything to a share. It reads the permissions on the share's root folder and checks whether a broad group has an Allow entry with write-type rights.

- Broad groups: Everyone, Authenticated Users, BUILTIN\Users, Domain Users, Domain Guests, Guests, Anonymous Logon, NETWORK.
- Write-type rights: write or append data, delete, delete subfolders and files, change permissions, take ownership, Modify, Full Control.

| Rating | Meaning |
|---|---|
| `BROAD-WRITE` | A broad group appears to have write access. Fix first. |
| `BROAD-READ` | A broad group has read access only. |
| `LIMITED` | No broad group on the permissions (a large group can still be listed; check the `.csv`/`.html`). |
| `UNKNOWN` | The permissions could not be read. |
| `DEFAULT` | Windows default share (`C$`, `ADMIN$`, ...). Not rated. |

## Limitations

- **Results reflect the account you run it as.** For an "open to all staff" view, run it as a standard user, not an admin. The script warns when the account is a Domain/Enterprise/Schema Admin, or when `C$`/`ADMIN$` opens (admin rights see everything).
- **Ratings come from the folder permissions, not share-level permissions.** Share-level permissions and deny entries are not evaluated (that needs admin on the server), so `BROAD-WRITE` is a strong indicator, not proof.
- **"Could not be tested" is not "closed".** Shares that time out or are offline are always listed separately.
- Windows only (uses the Win32 `NetShareEnum` API).

