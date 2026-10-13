$ErrorActionPreference = 'Stop'

$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1 -or $os.BuildNumber -ne '20348' -or $os.OSArchitecture -notmatch '64') {
    throw "Unexpected Windows image: $($os.Caption), build $($os.BuildNumber), $($os.OSArchitecture)"
}

$cloudbase = Join-Path $env:ProgramFiles 'Cloudbase Solutions\Cloudbase-Init'
foreach ($file in @('conf\cloudbase-init.conf', 'conf\cloudbase-init-unattend.conf', 'conf\Unattend.xml')) {
    if (-not (Test-Path (Join-Path $cloudbase $file))) { throw "Cloudbase-Init file is missing: $file" }
}
$mainConfig = Get-Content (Join-Path $cloudbase 'conf\cloudbase-init.conf') -Raw
if ($mainConfig -notmatch 'ConfigDriveService' -or $mainConfig -notmatch 'inject_user_password=true') {
    throw 'Cloudbase-Init is not configured for ConfigDrive password injection'
}

foreach ($driver in @('viostor', 'netkvm', 'vioser')) {
    $present = Get-WindowsDriver -Online -All | Where-Object { $_.Driver -match $driver -or $_.OriginalFileName -match $driver }
    if (-not $present) { throw "VirtIO driver is not staged: $driver" }
}
if (-not (Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue)) { throw 'QEMU Guest Agent is missing' }
if ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -ne 0) {
    throw 'RDP is not enabled in the guest'
}
$addresses = Get-NetFirewallRule -Name 'HFBuilderWinRM' -ErrorAction Stop | Get-NetFirewallAddressFilter
if ($addresses.RemoteAddress -notcontains '10.0.2.2') {
    throw 'Temporary WinRM firewall rule is not restricted to the QEMU gateway'
}
