# Smoke test for the Windows client, run by CI on a Windows runner as Administrator:
# installs vabbit with install.ps1 from a local folder, enrolls against the local
# control plane, runs the device as a service and checks the Wintun adapter, the
# status pipe, firewall rules, hosts names, file permissions, stop and leave.
#
#   powershell -File scripts/windows-smoke.ps1 -Assets DIR
#
# DIR holds vabbit-windows-amd64.exe, wintun-amd64.dll and SHA256SUMS. Needs bun.
param([Parameter(Mandatory)][string]$Assets)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$server = 'http://127.0.0.1:8787'
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$failed = $false

function Fail($msg) {
  Write-Host "::error title=windows smoke::$msg"
  Write-Host "FAIL $msg"
  $log = Join-Path $env:ProgramData 'vabbit\vabbit.log'
  if (Test-Path $log) { Write-Host '== vabbit.log'; Get-Content $log -Tail 40 }
  throw $msg
}
function Check($ok, $msg) { if ($ok) { Write-Host "ok   $msg" } else { Fail $msg } }
function WaitFor([scriptblock]$cond, $msg, $seconds = 30) {
  for ($i = 0; $i -lt $seconds * 2; $i++) {
    if (& $cond) { Write-Host "ok   $msg"; return }
    Start-Sleep -Milliseconds 500
  }
  Fail $msg
}

# Serve the release files to install.ps1 from a local web server.
$web = Start-Process -FilePath python -ArgumentList '-m', 'http.server', '8790', '--bind', '127.0.0.1' `
  -WorkingDirectory $Assets -PassThru -WindowStyle Hidden
$cp = $null
try {
  $env:VABBIT_BASE_URL = 'http://127.0.0.1:8790'
  WaitFor { try { (Invoke-WebRequest -UseBasicParsing "$($env:VABBIT_BASE_URL)/SHA256SUMS").StatusCode -eq 200 } catch { $false } } 'asset server up'
  & (Join-Path $root 'scripts\install.ps1')
  $v = Join-Path $env:ProgramFiles 'Vabbit\vabbit.exe'
  Check (Test-Path (Join-Path $env:ProgramFiles 'Vabbit\wintun.dll')) 'installer put vabbit.exe and wintun.dll in Program Files'
  Remove-Item Env:VABBIT_BASE_URL

  # Control plane: the edge script's local dev server, with a fresh admin token.
  $out = & $v admin-token
  $tok = ([regex]'vba_[A-Za-z0-9_-]{43}').Match(($out -join "`n")).Value
  $env:ADMIN_TOKEN_SHA256 = ([regex]'[0-9a-f]{64}').Match(($out -join "`n")).Value
  $cp = Start-Process -FilePath bun -ArgumentList 'run', 'dev' -WorkingDirectory (Join-Path $root 'edge') -PassThru -WindowStyle Hidden
  WaitFor { try { (Invoke-WebRequest -UseBasicParsing "$server/healthz").StatusCode -eq 200 } catch { $false } } 'control plane up'

  $env:VABBIT_ADMIN_PASSWORD = 'windows-smoke-test'
  $tok | & $v login --server $server
  Check ($LASTEXITCODE -eq 0) 'admin login'
  $key = { ([regex]'vbk_[A-Za-z0-9_-]{43}').Match(((& $v keys create) -join "`n")).Value }
  # A second device, so the Windows one has a peer and a name to resolve.
  $env:VABBIT_SETUP_KEY = & $key
  & $v up --server $server --name peer --iface vb9 --state-dir (Join-Path $env:TEMP 'vabbit-peer') --dry-run | Out-Null
  $env:VABBIT_SETUP_KEY = & $key
  & $v up --server $server --name win-smoke --dry-run
  Check ($LASTEXITCODE -eq 0) 'enrolled'
  Remove-Item Env:VABBIT_SETUP_KEY

  $acl = (Get-Acl (Join-Path $env:ProgramData 'vabbit\vb0.json')).Access | ForEach-Object { $_.IdentityReference.Value }
  Check (-not ($acl | Where-Object { $_ -notmatch 'SYSTEM|Administrators' })) "device state only readable by SYSTEM and Administrators ($($acl -join ', '))"

  $ip = ((& $v devices ls) | Where-Object { $_ -match '\swin-smoke\s' } | ForEach-Object { ($_ -split '\s+')[2] })
  & $v service install --iface vb0
  Check ($LASTEXITCODE -eq 0) 'service installed and started'
  WaitFor { (Get-NetIPAddress -InterfaceAlias vb0 -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -eq $ip } "adapter vb0 has $ip"
  Check ((Get-NetIPInterface -InterfaceAlias vb0 -AddressFamily IPv4).NlMtu -eq 1280) 'MTU 1280'
  WaitFor { (& $v status --iface vb0) -match 'peer' -and -not ((& $v status --iface vb0) -match 'not running') } 'vabbit status reads the running agent'
  WaitFor { Get-NetFirewallRule -DisplayName 'Vabbit vb0 WireGuard' -ErrorAction SilentlyContinue } 'firewall rules added'
  WaitFor { Select-String -Path $hostsFile -Pattern 'peer\.vabbit' -Quiet } 'hosts file has peer.vabbit'

  & $v down --iface vb0
  WaitFor { -not (Get-NetAdapter -Name vb0 -ErrorAction SilentlyContinue) } 'down stops the service and removes the adapter'
  Check (-not (Select-String -Path $hostsFile -Pattern 'BEGIN vabbit vb0' -Quiet)) 'hosts block removed'

  Start-Service vabbit-vb0
  WaitFor { (Get-NetIPAddress -InterfaceAlias vb0 -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -eq $ip } 'service starts again'
  & $v leave --iface vb0
  Check ($LASTEXITCODE -eq 0) 'leave'
  Check (-not (Get-Service vabbit-vb0 -ErrorAction SilentlyContinue)) 'leave removes the service'
  Check (-not (Get-NetFirewallRule -DisplayName 'Vabbit vb0 WireGuard' -ErrorAction SilentlyContinue)) 'leave removes the firewall rules'
  Check (-not ((& $v devices ls) -match 'win-smoke')) 'device gone from the network'
  Write-Host 'PASS'
} finally {
  foreach ($p in @($cp, $web)) { if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}
