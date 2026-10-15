$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$volume = Get-Volume -FileSystemLabel 'HFBUILDER'
if (-not $volume) { throw 'HFBUILDER payload CD is missing' }
$payload = "$($volume.DriveLetter):\"

& pnputil.exe /add-driver "$payload\drivers\*.inf" /subdirs
if ($LASTEXITCODE -ne 0) { throw "VirtIO driver staging failed: $LASTEXITCODE" }

foreach ($msi in @('virtio-win-gt-x64.msi', 'qemu-ga-x86_64.msi')) {
    $process = Start-Process msiexec.exe -ArgumentList @('/i', "$payload\$msi", '/qn', '/norestart') -Wait -PassThru
    if ($process.ExitCode -notin @(0, 1641, 3010)) { throw "$msi installation failed: $($process.ExitCode)" }
}

$qga = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
if ($qga) { Set-Service -Name $qga.Name -StartupType Automatic }

Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Remove-NetFirewallRule -Name 'HFBuilderWinRM' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'HFBuilderWinRM' -DisplayName 'Temporary HoneyForge Builder WinRM' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -RemoteAddress 10.0.2.2 | Out-Null
Restart-Service WinRM
