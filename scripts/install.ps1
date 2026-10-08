# Install the Vabbit client on Windows, and optionally join a network.
# Run in PowerShell as Administrator:
#
#   irm https://raw.githubusercontent.com/thomaskhub/vabbit/main/scripts/install.ps1 | iex
#
# Join a network in the same step (the setup key comes from `vabbit keys create`):
#
#   $env:VABBIT_SERVER = 'https://mynet.b-cdn.net'; $env:VABBIT_SETUP_KEY = 'vbk_...'
#   irm https://raw.githubusercontent.com/thomaskhub/vabbit/main/scripts/install.ps1 | iex
#
# Settings (environment variables), as in install.sh:
#   VABBIT_VERSION     release tag to install, e.g. v0.1.0 (default: latest)
#   VABBIT_SERVER      control plane URL; with VABBIT_SETUP_KEY, enroll and start the service
#   VABBIT_SETUP_KEY   one-time setup key
#   VABBIT_NAME        device name (default: computer name)
#   VABBIT_IFACE       WireGuard interface (default: vb0)
#   GITHUB_TOKEN       needed while the repository is private
#   VABBIT_REPO        GitHub repository (default: thomaskhub/vabbit)
#
# Installs vabbit.exe and wintun.dll into "C:\Program Files\Vabbit" and adds it to PATH.
# Every download is checked against the release's SHA256SUMS before anything is installed.

& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue' # much faster Invoke-WebRequest on Windows PowerShell 5
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  function Say($m) { Write-Host "vabbit: $m" }

  $repo = if ($env:VABBIT_REPO) { $env:VABBIT_REPO } else { 'thomaskhub/vabbit' }
  $version = if ($env:VABBIT_VERSION) { $env:VABBIT_VERSION } else { 'latest' }
  $iface = if ($env:VABBIT_IFACE) { $env:VABBIT_IFACE } else { 'vb0' }
  $dir = Join-Path $env:ProgramFiles 'Vabbit'

  $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $admin) { throw 'run PowerShell as Administrator' }
  $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "unsupported CPU $($env:PROCESSOR_ARCHITECTURE); amd64 and arm64 are available" }
  }

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("vabbit-" + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $cache = @{} # the release's API record, looked up once
    function Fetch($name) {
      $out = Join-Path $tmp $name
      if ($env:VABBIT_BASE_URL) { # a mirror, or a local server for testing
        Invoke-WebRequest -UseBasicParsing -Uri "$($env:VABBIT_BASE_URL)/$name" -OutFile $out
      } elseif ($env:GITHUB_TOKEN) {
        # Private repository: find the asset through the API, then download it.
        $h = @{ Authorization = "Bearer $($env:GITHUB_TOKEN)"; Accept = 'application/vnd.github+json' }
        if (-not $cache.release) {
          $rel = if ($version -eq 'latest') { 'latest' } else { "tags/$version" }
          $cache.release = Invoke-RestMethod -Headers $h -Uri "https://api.github.com/repos/$repo/releases/$rel"
        }
        $asset = $cache.release.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if (-not $asset) { throw "release $version has no asset $name" }
        $h.Accept = 'application/octet-stream'
        Invoke-WebRequest -UseBasicParsing -Headers $h -Uri $asset.url -OutFile $out
      } else {
        $base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $out
      }
      return $out
    }

    $exeName = "vabbit-windows-$arch.exe"
    $dllName = "wintun-$arch.dll"
    Say "downloading $exeName ($version) from $repo"
    $sums = Get-Content (Fetch 'SHA256SUMS')
    foreach ($name in @($exeName, $dllName)) {
      $file = Fetch $name
      $line = $sums | Where-Object { $_ -match "^([0-9a-f]{64}) \*?$([regex]::Escape($name))$" } | Select-Object -First 1
      if (-not $line) { throw "SHA256SUMS does not list $name" }
      $want = $line.Substring(0, 64)
      $got = (Get-FileHash -Algorithm SHA256 $file).Hash.ToLower()
      if ($got -ne $want) { throw "checksum mismatch for $name, nothing installed" }
    }

    # An upgrade: stop the running service first, the files are in use.
    $svc = Get-Service -Name "vabbit-$iface" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name $svc.Name -Force }

    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item (Join-Path $tmp $exeName) (Join-Path $dir 'vabbit.exe') -Force
    Copy-Item (Join-Path $tmp $dllName) (Join-Path $dir 'wintun.dll') -Force
    $vabbit = Join-Path $dir 'vabbit.exe'
    Say "installed $vabbit ($(& $vabbit version))"

    $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (($path -split ';') -notcontains $dir) {
      [Environment]::SetEnvironmentVariable('Path', "$path;$dir", 'Machine')
      Say "added $dir to PATH (open a new terminal to use it)"
    }
    if ($env:Path -notlike "*$dir*") { $env:Path += ";$dir" }

    if ($env:VABBIT_SETUP_KEY -and $env:VABBIT_SERVER) {
      $a = @('up', '--server', $env:VABBIT_SERVER, '--iface', $iface, '--dry-run')
      if ($env:VABBIT_NAME) { $a += @('--name', $env:VABBIT_NAME) }
      & $vabbit @a
      if ($LASTEXITCODE -ne 0) { throw 'enrolling failed' }
      & $vabbit service install --iface $iface
      if ($LASTEXITCODE -ne 0) { throw 'installing the service failed' }
      Say "joined; check it with: vabbit status --iface $iface"
    } elseif ($svc) {
      Start-Service -Name $svc.Name
      Say "restarted $($svc.Name)"
    } else {
      Say 'done. Join a network with (as Administrator):'
      Say '  $env:VABBIT_SETUP_KEY = ''vbk_...''; vabbit up --server https://mynet.b-cdn.net --dry-run'
      Say "  vabbit service install --iface $iface"
    }
  } finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}
