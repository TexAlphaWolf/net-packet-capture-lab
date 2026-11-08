# End to end inside the image, from Windows PowerShell: a synthetic capture is written to a volume, analysed, turned
# into a report and filtered (read-only root, no capabilities, no network). Needs Docker Desktop.
# Usage: .\tools\docker_e2e.ps1 [-Image pcaplab]
param([string]$Image = "pcaplab")
$ErrorActionPreference = "Stop"

$id = Get-Random
$vol = "pcaplab-e2e-$id"
$secure = @("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "none", "-v", "${vol}:/data")

# Windows PowerShell 5.1 turns a program's message on stderr into an error under "Stop": the commands that are
# expected to fail run with errors not terminating, and only their exit code is looked at.
function Invoke-PlCode([int[]]$Allowed, [string[]]$PlArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $out = docker run --rm @secure $Image @PlArgs 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($Allowed -notcontains $code) { throw "pcaplab $PlArgs exited with $code : $out" }
    ($out | Out-String)
}
function Invoke-Pl([string[]]$PlArgs) { Invoke-PlCode @(0) $PlArgs }
function Read-Volume($path) {
    $out = docker run --rm --entrypoint cat -v "${vol}:/data" $Image $path
    if ($LASTEXITCODE -ne 0) { throw "cannot read $path" }
    ($out | Out-String)
}
function Assert-Contains($text, $needle) { if ($text -notmatch [regex]::Escape($needle)) { throw "expected '$needle' in: $text" } }
function Assert-Missing($text, $needle) { if ($text -match [regex]::Escape($needle)) { throw "did not expect '$needle' in: $text" } }

try {
    docker volume create $vol | Out-Null
    docker run --rm --user 0 -v "${vol}:/data" --entrypoint chown $Image 10001 /data
    if ($LASTEXITCODE -ne 0) { throw "could not prepare the volume" }

    Assert-Contains (Invoke-Pl @("sample", "-o", "demo.pcap", "--duration", "600", "--truth", "truth.json")) "things injected"
    $found = Invoke-PlCode @(1) @("findings", "demo.pcap")   # exit code 1: there are findings
    foreach ($want in "TCP port scan from 203.0.113.50", "Possible DNS tunnel", "HTTP Basic login", "FTP password", "claimed by", "Regular connections") {
        Assert-Contains $found $want
    }
    Assert-Missing $found "S3cret"
    Assert-Missing $found "hunter2"

    $summary = Invoke-Pl @("summary", "demo.pcap")
    Assert-Contains $summary "Top hosts by bytes"
    Assert-Contains $summary "TLS server names"
    $flows = (Invoke-Pl @("flows", "demo.pcap", "--top", "3")).Trim() -split "`r?`n"
    if ($flows.Count -ne 4) { throw "expected a header and 3 flows, got $($flows.Count) lines" }

    Invoke-Pl @("report", "demo.pcap", "-o", "out/report.html") | Out-Null
    $page = Read-Volume "/data/out/report.html"
    Assert-Contains $page "default-src 'none'"
    Assert-Missing $page "<script"
    Assert-Missing $page "S3cret"

    $anon = Invoke-PlCode @(0, 1) @("findings", "demo.pcap", "--anonymize")
    Assert-Missing $anon "203.0.113.50"
    Assert-Missing $anon "10.0.0.23"

    Invoke-Pl @("filter", "demo.pcap", "dns and host 10.0.0.23", "-o", "dns.pcap") | Out-Null
    $dns = Invoke-PlCode @(0, 1) @("findings", "dns.pcap")
    Assert-Contains $dns "Possible DNS tunnel"
    Assert-Missing $dns "port scan"

    Invoke-PlCode @(2) @("summary", "nope.pcap") | Out-Null     # a missing file is exit code 2
    Write-Host "docker end-to-end: OK"
}
finally {
    $ErrorActionPreference = "Continue"
    docker volume rm -f $vol 2>&1 | Out-Null
}
