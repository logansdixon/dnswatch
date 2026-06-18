<#
.SYNOPSIS
    Continuously test DNS resolution across up to 4 DNS servers, from a plain
    PowerShell window. No modules to install, no other language required.

.DESCRIPTION
    Incident-response tool for a DNS outage. Sends randomized lookups of
    known-good domains to each server and shows a live pass/fail + latency
    dashboard, logging every query to CSV for the post-incident record.

    DNS is done with raw UDP via .NET sockets (System.Net.Sockets.UdpClient),
    which ships with PowerShell - so this:
      * queries ANY server by IP, including internal/corporate resolvers,
      * supports a custom port via  <ip>#<port>  (e.g. 10.1.1.53#5353),
      * honours a real, configurable -Timeout,
      * runs on Windows PowerShell 5.1 AND PowerShell 7 (Windows/Linux/macOS).

    Note: queries are sent without EDNS, so very large answers (e.g. some TXT
    sets) may be truncated. For the A/AAAA/MX/NS health checks this tool is for,
    that's a non-issue.

.PARAMETER Server     1 to 4 DNS servers as <ip> or <ip>#<port> (IPv4 or IPv6).
.PARAMETER Interval   Seconds between query rounds (default 2).
.PARAMETER Timeout    Per-query timeout in seconds (default 2; retries use half this).
.PARAMETER Type       Record type: A, AAAA, MX, NS, TXT, SOA, PTR, SRV, CAA (default A).
.PARAMETER Count      Number of rounds then stop (0 = run forever, the default).
.PARAMETER Retries    Retry transient failures up to N times per query (default 1; retries use Timeout/2; 0 = raw).
.PARAMETER DomainsFile  File with one domain per line (overrides built-in pool). '#' = comment.
.PARAMETER Log        CSV log path (default .\dnswatch_log.csv).
.PARAMETER NoValidate Skip the startup domain-pool sanity check.
.PARAMETER Simple     Plain line-by-line output instead of the live dashboard.

.EXAMPLE
    .\dnswatch.ps1 10.1.1.53 10.1.2.53 8.8.8.8 1.1.1.1
.EXAMPLE
    .\dnswatch.ps1 10.1.1.53 192.168.1.1#5353 9.9.9.9 -Interval 1 -Timeout 2
.EXAMPLE
    .\dnswatch.ps1 10.1.1.53 -Type AAAA -DomainsFile .\internal.txt -Log incident.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateCount(1, 4)]
    [string[]]$Server,

    [double]$Interval = 2,
    [double]$Timeout = 2,
    [string]$Type = 'A',
    [int]$Count = 0,
    [int]$Retries = 1,
    [string]$DomainsFile,
    [string]$Log = 'dnswatch_log.csv',
    [switch]$NoValidate,
    [switch]$Simple
)

$QTypeMap = @{ A = 1; NS = 2; CNAME = 5; SOA = 6; PTR = 12; MX = 15; TXT = 16; AAAA = 28; SRV = 33; CAA = 257 }
$RCodeName = @{ 0 = 'NOERROR'; 1 = 'FORMERR'; 2 = 'SERVFAIL'; 3 = 'NXDOMAIN'; 4 = 'NOTIMP'; 5 = 'REFUSED' }

# A spread of globally distributed, stable domains across *different* authoritative
# DNS providers, so we're not just measuring one CDN's health.
$DefaultDomains = @(
    'google.com', 'cloudflare.com', 'microsoft.com', 'amazon.com', 'apple.com',
    'github.com', 'wikipedia.org', 'mozilla.org', 'cisco.com', 'akamai.com',
    'fastly.com', 'netflix.com', 'ietf.org', 'debian.org', 'ubuntu.com',
    'python.org', 'stackoverflow.com', 'reddit.com', 'bbc.co.uk', 'nytimes.com',
    'salesforce.com', 'oracle.com', 'ibm.com', 'intel.com', 'nvidia.com',
    'adobe.com', 'dropbox.com', 'slack.com', 'zoom.us', 'office.com',
    'bing.com', 'yahoo.com', 'wordpress.org', 'gnu.org', 'kernel.org',
    'archive.org', 'cnn.com', 'paypal.com', 'ebay.com', 'linkedin.com',
    'spotify.com', 'twitch.tv', 'nucor.com', 'azure.com'
)

# ---- Raw DNS over UDP (byte logic verified against live resolvers) ----------

function New-DnsQuery {
    param([string]$Name, [int]$QType)
    $id = Get-Random -Minimum 0 -Maximum 65536
    $b = New-Object System.Collections.Generic.List[byte]
    $b.Add([byte]($id -shr 8)); $b.Add([byte]($id -band 0xFF))   # transaction id
    $b.Add(0x01); $b.Add(0x00)                                   # flags: recursion desired
    $b.Add(0x00); $b.Add(0x01)                                   # QDCOUNT = 1
    $b.AddRange([byte[]]@(0, 0, 0, 0, 0, 0))                     # AN/NS/AR counts = 0
    foreach ($label in ($Name -split '\.')) {
        if ($label.Length -gt 0) {
            $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
            $b.Add([byte]$lb.Length); $b.AddRange($lb)
        }
    }
    $b.Add(0x00)                                                 # root label / end of QNAME
    $b.Add([byte]($QType -shr 8)); $b.Add([byte]($QType -band 0xFF))
    $b.Add(0x00); $b.Add(0x01)                                   # QCLASS = IN
    return [pscustomobject]@{ Id = $id; Bytes = $b.ToArray() }
}

function Get-U16 { param($Data, [int]$Off) (([int]$Data[$Off] -shl 8) -bor [int]$Data[$Off + 1]) }

function Read-DnsName {
    param($Data, [int]$Offset)
    $labels = New-Object System.Collections.Generic.List[string]
    $jumped = $false
    $next = $Offset
    while ($true) {
        $len = [int]$Data[$Offset]
        if ($len -eq 0) { $Offset++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            $ptr = (($len -band 0x3F) -shl 8) -bor [int]$Data[$Offset + 1]
            if (-not $jumped) { $next = $Offset + 2 }
            $Offset = $ptr; $jumped = $true; continue
        }
        $Offset++
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Data, $Offset, $len))
        $Offset += $len
    }
    $nextOff = $(if ($jumped) { $next } else { $Offset })
    return [pscustomobject]@{ Name = ($labels -join '.'); Next = $nextOff }
}

function Read-DnsResponse {
    param($Data)
    $id = Get-U16 $Data 0
    $rcode = (Get-U16 $Data 2) -band 0x000F
    $qd = Get-U16 $Data 4
    $an = Get-U16 $Data 6
    $off = 12
    for ($i = 0; $i -lt $qd; $i++) { $off = (Read-DnsName $Data $off).Next + 4 }
    $answers = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $an; $i++) {
        $off = (Read-DnsName $Data $off).Next
        $rtype = Get-U16 $Data $off
        $rdlen = Get-U16 $Data ($off + 8)
        $off += 10
        switch ($rtype) {
            1  { if ($rdlen -eq 4)  { $ipb = New-Object byte[] 4;  [Array]::Copy($Data, $off, $ipb, 0, 4);  $answers.Add(([System.Net.IPAddress]::new($ipb)).ToString()) } }
            28 { if ($rdlen -eq 16) { $ipb = New-Object byte[] 16; [Array]::Copy($Data, $off, $ipb, 0, 16); $answers.Add(([System.Net.IPAddress]::new($ipb)).ToString()) } }
            5  { $answers.Add((Read-DnsName $Data $off).Name) }
            2  { $answers.Add((Read-DnsName $Data $off).Name) }
            15 { $answers.Add(('{0} {1}' -f (Get-U16 $Data $off), (Read-DnsName $Data ($off + 2)).Name)) }
            16 { $t = ''; $k = $off; $end = $off + $rdlen
                 while ($k -lt $end) { $sl = [int]$Data[$k]; $t += [System.Text.Encoding]::ASCII.GetString($Data, $k + 1, $sl); $k += 1 + $sl }
                 $answers.Add($t) }
            default { $answers.Add("type$rtype") }
        }
        $off += $rdlen
    }
    return [pscustomobject]@{ Id = $id; RCode = $rcode; AnCount = $an; Answers = $answers.ToArray() }
}

function Invoke-DnsQuery {
    # One lookup over raw UDP. Returns @{ Category; Ms; Result }.
    param([string]$Ip, [int]$Port, [string]$Domain, [string]$TypeName, [double]$Timeout)
    $qtype = $QTypeMap[$TypeName]
    $query = New-DnsQuery -Name $Domain -QType $qtype
    $udp = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
        $remote = New-Object System.Net.IPEndPoint($addr, $Port)
        $udp = New-Object System.Net.Sockets.UdpClient($addr.AddressFamily)
        $udp.Client.ReceiveTimeout = [int]($Timeout * 1000)
        [void]$udp.Send($query.Bytes, $query.Bytes.Length, $remote)
        $anyEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $data = $udp.Receive([ref]$anyEP)
        $sw.Stop()
        $ms = [int][math]::Round($sw.Elapsed.TotalMilliseconds)
        $resp = Read-DnsResponse $data
        if ($resp.Id -ne $query.Id) {
            return [pscustomobject]@{ Category = 'transient'; Ms = $null; Result = 'ID mismatch (stray packet)' }
        }
        if ($resp.RCode -eq 0 -and $resp.AnCount -gt 0) {
            $res = $(if ($resp.Answers.Count) { ($resp.Answers | Select-Object -First 2) -join ', ' } else { '(answer)' })
            return [pscustomobject]@{ Category = 'ok'; Ms = $ms; Result = $res }
        }
        if ($resp.RCode -eq 0) { return [pscustomobject]@{ Category = 'negative'; Ms = $ms; Result = "NoAnswer (no $TypeName record)" } }
        if ($resp.RCode -eq 3) { return [pscustomobject]@{ Category = 'negative'; Ms = $ms; Result = 'NXDOMAIN (no such name)' } }
        $rc = $(if ($RCodeName.ContainsKey($resp.RCode)) { $RCodeName[$resp.RCode] } else { "RCODE$($resp.RCode)" })
        return [pscustomobject]@{ Category = 'transient'; Ms = $null; Result = $rc }
    }
    catch [System.Net.Sockets.SocketException] {
        $sw.Stop()
        if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            return [pscustomobject]@{ Category = 'transient'; Ms = $null; Result = ("TIMEOUT (>{0}s)" -f $Timeout) }
        }
        return [pscustomobject]@{ Category = 'transient'; Ms = $null; Result = ("SOCKET: " + $_.Exception.SocketErrorCode) }
    }
    catch {
        $sw.Stop()
        return [pscustomobject]@{ Category = 'transient'; Ms = $null; Result = ('ERROR: ' + (($_.Exception.Message) -replace '\s+', ' ').Trim()) }
    }
    finally {
        if ($udp) { $udp.Close() }
    }
}

function Invoke-DnsQueryWithRetries {
    # Retry transient failures (timeout/servfail) up to $Retries times, the way a
    # real stub resolver does. Definitive negatives are returned immediately.
    # Retries use half the timeout so a dead server doesn't stall the dashboard:
    # one packet loss against a healthy server costs +Timeout/2, not +Timeout.
    param([string]$Ip, [int]$Port, [string]$Domain, [string]$TypeName, [double]$Timeout, [int]$Retries)
    $r = Invoke-DnsQuery -Ip $Ip -Port $Port -Domain $Domain -TypeName $TypeName -Timeout $Timeout
    $attempt = 0
    $retryTimeout = $Timeout / 2.0
    while ($r.Category -eq 'transient' -and $attempt -lt $Retries) {
        $attempt++
        $r = Invoke-DnsQuery -Ip $Ip -Port $Port -Domain $Domain -TypeName $TypeName -Timeout $retryTimeout
    }
    $ok = $r.Category -eq 'ok'
    $result = $r.Result
    if ($ok -and $attempt -gt 0) {
        $word = $(if ($attempt -eq 1) { 'retry' } else { 'retries' })
        $result = "$result  [ok after $attempt $word]"
    }
    return [pscustomobject]@{ Ok = $ok; Ms = $r.Ms; Result = $result; Category = $r.Category }
}

# ---- Concurrency: RunspacePool so per-round queries hit max(query), not sum --

function New-DnsRunspacePool {
    # Build a runspace pool with the DNS helper functions and lookup tables
    # pre-loaded. Workers can then call Invoke-DnsQueryWithRetries directly.
    param([int]$MaxThreads)
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in 'New-DnsQuery', 'Get-U16', 'Read-DnsName', 'Read-DnsResponse', 'Invoke-DnsQuery', 'Invoke-DnsQueryWithRetries') {
        $def = (Get-Item function:\$fn).Definition
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $fn, $def))
    }
    foreach ($name in 'QTypeMap', 'RCodeName') {
        $val = Get-Variable -Name $name -ValueOnly -Scope Script
        $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry $name, $val, ''))
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $MaxThreads), $iss, $Host)
    $pool.Open()
    return $pool
}

function Invoke-ParallelDnsQueries {
    # Submit one DNS query per job (Ip/Port/Domain) to the runspace pool and
    # return @{ Job; Result } per input job, in submission order. Mirrors
    # Python's ThreadPoolExecutor pattern in dnswatch.py:341-352.
    param($Pool, $Jobs, [string]$TypeName, [double]$Timeout, [int]$Retries)
    $async = New-Object System.Collections.Generic.List[object]
    foreach ($j in $Jobs) {
        $ps = [powershell]::Create().AddScript({
                param($ip, $port, $domain, $type, $timeout, $retries)
                Invoke-DnsQueryWithRetries -Ip $ip -Port $port -Domain $domain -TypeName $type -Timeout $timeout -Retries $retries
            }).AddArgument($j.Ip).AddArgument($j.Port).AddArgument($j.Domain).AddArgument($TypeName).AddArgument($Timeout).AddArgument($Retries)
        $ps.RunspacePool = $Pool
        $async.Add([pscustomobject]@{ Job = $j; PS = $ps; Handle = $ps.BeginInvoke() })
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in $async) {
        try {
            $r = $a.PS.EndInvoke($a.Handle)
            $result = $(if ($r.Count -gt 0) { $r[0] } else { [pscustomobject]@{ Ok = $false; Ms = $null; Result = 'no result'; Category = 'transient' } })
        }
        catch {
            $result = [pscustomobject]@{ Ok = $false; Ms = $null; Result = 'WORKER: ' + $_.Exception.Message; Category = 'transient' }
        }
        finally { $a.PS.Dispose() }
        $out.Add([pscustomobject]@{ Job = $a.Job; Result = $result })
    }
    return $out.ToArray()
}

function Initialize-DomainPool {
    # Drop domains that get a definitive negative (no record) on every server -
    # those would count as a failure every round and skew the success rate
    # (e.g. apex cloudfront.net has no A record). Timeouts never drop a domain:
    # during an outage the servers, not the domain, may be the problem.
    param([string[]]$Domains, $Servers, [string]$TypeName, [double]$Timeout, [int]$Retries, $Pool)
    $vTimeout = [Math]::Min($Timeout, 2.0)
    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($d in $Domains) {
        foreach ($s in $Servers) {
            $jobs.Add([pscustomobject]@{ Ip = $s.Ip; Port = $s.Port; Domain = $d })
        }
    }
    $results = Invoke-ParallelDnsQueries -Pool $Pool -Jobs $jobs.ToArray() -TypeName $TypeName -Timeout $vTimeout -Retries $Retries
    $byDomain = @{}
    foreach ($d in $Domains) { $byDomain[$d] = New-Object System.Collections.Generic.List[string] }
    foreach ($r in $results) { $byDomain[$r.Job.Domain].Add($r.Result.Category) }
    $usable = New-Object System.Collections.Generic.List[string]
    $dropped = New-Object System.Collections.Generic.List[string]
    $unknown = New-Object System.Collections.Generic.List[string]
    foreach ($d in $Domains) {
        $cats = $byDomain[$d]
        if ($cats -contains 'ok')             { $usable.Add($d) }
        elseif ($cats -contains 'negative')   { $dropped.Add($d) }
        else                                  { $unknown.Add($d); $usable.Add($d) }
    }
    return [pscustomobject]@{ Usable = $usable.ToArray(); Dropped = $dropped.ToArray(); Unknown = $unknown.ToArray() }
}

# ---- Display ---------------------------------------------------------------

function Write-Cell {
    param([string]$Text, [int]$Width, [string]$Align = 'l', $Color)
    $t = "$Text"
    if ($t.Length -gt $Width) { $t = $t.Substring(0, $Width) }
    $t = $(if ($Align -eq 'r') { $t.PadLeft($Width) } else { $t.PadRight($Width) })
    if ($Color) { Write-Host $t -NoNewline -ForegroundColor $Color } else { Write-Host $t -NoNewline }
}

function Write-EventLine {
    param([string]$Line)
    foreach ($tok in ($Line -split ' ')) {
        if ($tok -match '=OK/')      { Write-Host "$tok " -NoNewline -ForegroundColor Green }
        elseif ($tok -match '=FAIL') { Write-Host "$tok " -NoNewline -ForegroundColor Red }
        else                         { Write-Host "$tok " -NoNewline }
    }
    Write-Host ''
}

function Show-Dashboard {
    param($Stats, [int]$Rounds, $Started, [string]$LastDomain, $Events, [string]$Type, [double]$Interval, [int]$Retries)
    $elapsed = [int]((Get-Date) - $Started).TotalSeconds
    $elapsedStr = '{0}m{1:d2}s' -f [int]($elapsed / 60), ($elapsed % 60)
    Clear-Host
    Write-Host ''
    Write-Host ("  DNS Watch   type={0}  interval={1}s  timeout={2}s  retries={3}  rounds={4}  elapsed={5}  last={6}" -f `
            $Type, $Interval, $script:Timeout, $Retries, $Rounds, $elapsedStr, $LastDomain) -ForegroundColor Cyan
    Write-Host ''
    Write-Host '    ' -NoNewline
    Write-Cell 'DNS Server' 20; Write-Cell 'Queries' 8 'r'; Write-Cell 'OK' 6 'r'
    Write-Cell 'Fail' 6 'r'; Write-Cell 'Success' 9 'r'; Write-Cell 'Last ms' 9 'r'; Write-Cell 'Avg ms' 9 'r'
    Write-Host '  Last result'
    Write-Host ('  ' + ('-' * 88)) -ForegroundColor DarkGray

    foreach ($s in $Stats) {
        $pct = $(if ($s.Queries) { $s.Ok / $s.Queries * 100 } else { 0 })
        $avg = $(if ($s.RecentMs.Count) { [int]($s.RecentMs | Measure-Object -Average).Average } else { $null })
        if ($null -eq $s.LastOk)      { $dotColor = 'DarkGray'; $pctColor = 'DarkGray' }
        elseif ($s.LastOk)            { $dotColor = 'Green'; $pctColor = $(if ($pct -ge 99) { 'Green' } else { 'Yellow' }) }
        else                          { $dotColor = 'Red'; $pctColor = 'Red' }
        $dot = $(if ($null -eq $s.LastOk) { 'o' } else { [char]0x25CF })

        Write-Host '  ' -NoNewline
        Write-Host ("{0} " -f $dot) -NoNewline -ForegroundColor $dotColor
        Write-Cell $s.Label 20
        Write-Cell $s.Queries 8 'r'
        Write-Cell $s.Ok 6 'r' 'Green'
        Write-Cell $s.Fail 6 'r' 'Red'
        Write-Cell ('{0:N1}%' -f $pct) 9 'r' $pctColor
        Write-Cell $(if ($null -ne $s.LastMs) { $s.LastMs } else { '-' }) 9 'r'
        Write-Cell $(if ($null -ne $avg) { $avg } else { '-' }) 9 'r'
        Write-Host ("  " + $s.LastResult)
    }
    Write-Host ''
    Write-Host '  recent activity:' -ForegroundColor DarkGray
    foreach ($e in $Events) { Write-Host '  ' -NoNewline; Write-EventLine $e }
    Write-Host ''
    Write-Host '  Ctrl+C to stop' -ForegroundColor DarkGray
}

function Show-Summary {
    param($Stats, [int]$Rounds, $Started, [string]$Log)
    $elapsed = [int]((Get-Date) - $Started).TotalSeconds
    $elapsedStr = '{0}m{1:d2}s' -f [int]($elapsed / 60), ($elapsed % 60)
    Write-Host ''
    Write-Host ('=' * 66)
    Write-Host ("  SUMMARY  ($Rounds rounds, $elapsedStr)")
    Write-Host ('=' * 66)
    foreach ($s in $Stats) {
        $pct = $(if ($s.Queries) { $s.Ok / $s.Queries * 100 } else { 0 })
        $avg = $(if ($s.Ok) { '{0}ms' -f [int]($s.TotalMs / $s.Ok) } else { 'n/a' })
        if ($pct -ge 99)     { $verdict = 'HEALTHY';      $vc = 'Green' }
        elseif ($pct -ge 50) { $verdict = 'DEGRADED';     $vc = 'Yellow' }
        else                 { $verdict = 'DOWN/FAILING'; $vc = 'Red' }
        Write-Host ("  {0}  {1,6:N1}% ok  ({2}/{3})  avg {4,-7} -> " -f `
                $s.Label.PadRight(22), $pct, $s.Ok, $s.Queries, $avg) -NoNewline
        Write-Host $verdict -ForegroundColor $vc
    }
    Write-Host ('=' * 66)
    Write-Host "  CSV log written to: $Log"
}

function Wait-Interval {
    param([double]$Seconds, [bool]$PollKeys)
    $until = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $until) {
        if ($PollKeys) {
            try {
                if ([Console]::KeyAvailable) {
                    $k = [Console]::ReadKey($true)
                    if ($k.Key -eq [ConsoleKey]::C -and ($k.Modifiers -band [ConsoleModifiers]::Control)) { return $true }
                }
            }
            catch { }
        }
        Start-Sleep -Milliseconds 80
    }
    return $false
}

# ---- Setup -----------------------------------------------------------------

$Type = $Type.ToUpper()
if (-not $QTypeMap.ContainsKey($Type)) {
    throw "Unsupported record type '$Type'. Supported: $(($QTypeMap.Keys | Sort-Object) -join ', ')"
}

$servers = foreach ($spec in $Server) {
    $ip = $spec; $port = 53
    if ($spec -match '#') {
        $bits = $spec -split '#', 2
        $ip = $bits[0]
        if (-not [int]::TryParse($bits[1], [ref]$port)) { throw "Invalid port in '$spec'." }
    }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$addr)) { throw "'$ip' is not a valid IPv4/IPv6 address." }
    $label = $(if ($port -eq 53) { $ip } else { "$ip#$port" })
    [pscustomobject]@{ Ip = $ip; Port = $port; Label = $label }
}

$domains = $(if ($DomainsFile) {
        if (-not (Test-Path $DomainsFile)) { throw "Domains file not found: $DomainsFile" }
        @(Get-Content $DomainsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    }
    else { $DefaultDomains })
if (-not $domains -or $domains.Count -eq 0) { throw 'No domains to test.' }

$stats = foreach ($srv in $servers) {
    [pscustomobject]@{
        Ip = $srv.Ip; Port = $srv.Port; Label = $srv.Label; Queries = 0; Ok = 0; Fail = 0; TotalMs = 0.0
        RecentMs = (New-Object System.Collections.Generic.List[double]); LastMs = $null
        LastOk = $null; LastResult = ''; ConsecutiveFail = 0
    }
}

$runspacePool = New-DnsRunspacePool -MaxThreads ([Math]::Max($servers.Count, 30))

if (-not $NoValidate) {
    Write-Host 'validating domain pool...' -ForegroundColor DarkGray
    $poolResult = Initialize-DomainPool -Domains $domains -Servers $servers -TypeName $Type -Timeout $Timeout -Retries $Retries -Pool $runspacePool
    if ($poolResult.Dropped.Count -gt 0) {
        Write-Host ("dropped {0} domain(s) with no {1} record: {2}" -f $poolResult.Dropped.Count, $Type, ($poolResult.Dropped -join ', ')) -ForegroundColor Yellow
    }
    if ($poolResult.Unknown.Count -eq $domains.Count) {
        Write-Host 'WARNING: no server answered any startup probe - servers may be down or no connectivity. Keeping full pool; failures are real.' -ForegroundColor Red
    }
    elseif ($poolResult.Unknown.Count -gt 0) {
        Write-Host ("note: {0} domain(s) inconclusive at startup (timeouts), kept in pool" -f $poolResult.Unknown.Count) -ForegroundColor DarkGray
    }
    if ($poolResult.Usable.Count -gt 0) { $domains = $poolResult.Usable }
    Start-Sleep -Milliseconds 800
}

# Open the CSV log (overwrite) and write the header. Resolve to a native filesystem
# path first - on UNC/WSL/PSDrive locations Get-Location returns a provider-qualified
# path (Microsoft.PowerShell.Core\FileSystem::...) that .NET's StreamWriter can't parse.
$Log = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Log)
try {
    $writer = [System.IO.StreamWriter]::new($Log, $false)
}
catch {
    throw "Could not open log file '$Log': $($_.Exception.Message). Use -Log <path> to choose a writable location."
}
$writer.WriteLine('timestamp,server,domain,type,ok,latency_ms,result')

$events = New-Object System.Collections.Generic.List[string]
$started = Get-Date
$rounds = 0
$lastPick = $null
$lastDomain = ''

$pollKeys = $false
try { [Console]::TreatControlCAsInput = $true; $pollKeys = $true } catch { $pollKeys = $false }

if ($Simple) {
    Write-Host ("DNS Watch  type={0} interval={1}s timeout={2}s  servers: {3}  (Ctrl+C to stop)" -f `
            $Type, $Interval, $Timeout, ($servers.Label -join ', '))
}

# ---- Main loop -------------------------------------------------------------

try {
    while ($true) {
        do { $domain = $domains | Get-Random } while ($domain -eq $lastPick -and $domains.Count -gt 1)
        $lastPick = $domain
        $lastDomain = $domain
        $rounds++
        $ts = (Get-Date).ToString('HH:mm:ss')

        # Submit all server queries in parallel; round duration is bounded by
        # the slowest single query, not the sum.
        $jobs = foreach ($s in $stats) {
            [pscustomobject]@{ Ip = $s.Ip; Port = $s.Port; Domain = $domain; Tag = $s }
        }
        $results = Invoke-ParallelDnsQueries -Pool $runspacePool -Jobs @($jobs) -TypeName $Type -Timeout $Timeout -Retries $Retries

        $parts = @()
        foreach ($r in $results) {
            $s = $r.Job.Tag
            $res = $r.Result

            $s.Queries++
            $s.LastOk = $res.Ok
            $s.LastMs = $res.Ms
            $s.LastResult = $res.Result
            if ($res.Ok) {
                $s.Ok++; $s.ConsecutiveFail = 0
                if ($null -ne $res.Ms) {
                    $s.TotalMs += $res.Ms
                    $s.RecentMs.Add([double]$res.Ms)
                    if ($s.RecentMs.Count -gt 20) { $s.RecentMs.RemoveAt(0) }
                }
            }
            else { $s.Fail++; $s.ConsecutiveFail++ }

            $msStr = $(if ($null -ne $res.Ms) { $res.Ms } else { '' })
            $safe = ($res.Result -replace '"', '""')
            $writer.WriteLine(('{0},{1},{2},{3},{4},{5},"{6}"' -f `
                    (Get-Date).ToString('s'), $s.Label, $domain, $Type, $res.Ok, $msStr, $safe))

            $mark = $(if ($res.Ok) { 'OK' } else { 'FAIL' })
            $msShow = $(if ($null -ne $res.Ms) { $res.Ms } else { '-' })
            $parts += ('{0}={1}/{2}ms' -f $s.Label, $mark, $msShow)
        }
        $writer.Flush()

        $eventLine = '{0}  {1}  {2}' -f $ts, $domain.PadRight(22), ($parts -join '  ')
        $events.Add($eventLine)
        if ($events.Count -gt 10) { $events.RemoveAt(0) }

        if ($Simple) { Write-Host $eventLine }
        else { Show-Dashboard -Stats $stats -Rounds $rounds -Started $started -LastDomain $lastDomain -Events $events -Type $Type -Interval $Interval -Retries $Retries }

        if ($Count -gt 0 -and $rounds -ge $Count) { break }
        if (Wait-Interval -Seconds $Interval -PollKeys $pollKeys) { break }
    }
}
finally {
    if ($pollKeys) { try { [Console]::TreatControlCAsInput = $false } catch { } }
    if ($writer) { $writer.Flush(); $writer.Close() }
    if ($runspacePool) { try { $runspacePool.Close(); $runspacePool.Dispose() } catch { } }
    Show-Summary -Stats $stats -Rounds $rounds -Started $started -Log $Log
}
