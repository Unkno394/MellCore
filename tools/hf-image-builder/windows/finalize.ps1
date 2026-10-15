param([switch]$AsSystem)

$ErrorActionPreference = 'Stop'

if (-not $AsSystem) {
    $script = $MyInvocation.MyCommand.Path
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -AsSystem"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    Register-ScheduledTask -TaskName 'HoneyForgeImageFinalize' -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName 'HoneyForgeImageFinalize'
    exit 0
}

Start-Sleep -Seconds 5

function Remove-SensitiveFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Path
    $length = $item.Length
    $stream = [System.IO.File]::Open($Path, 'Open', 'Write', 'None')
    try {
        $zeros = New-Object byte[] 65536
        while ($length -gt 0) {
            $count = [Math]::Min($zeros.Length, $length)
            $stream.Write($zeros, 0, $count)
            $length -= $count
        }
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Remove-Item -LiteralPath $Path -Force
}

Remove-NetFirewallRule -Name 'HFBuilderWinRM' -ErrorAction SilentlyContinue
Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Stop-Service WinRM -Force -ErrorAction SilentlyContinue
Set-Service WinRM -StartupType Disabled

$builderUser = Get-LocalUser -Name 'hfbuild' -ErrorAction Stop
$builderSid = $builderUser.SID.Value
& net.exe user hfbuild /delete | Out-Null
if ($LASTEXITCODE -ne 0) { throw "temporary builder account removal failed: $LASTEXITCODE" }
$builderProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $builderSid }
if ($builderProfile) {
    for ($attempt = 0; $attempt -lt 30 -and $builderProfile.Loaded; $attempt++) {
        Start-Sleep -Seconds 1
        $builderProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $builderSid }
    }
    if ($builderProfile -and $builderProfile.Loaded) { throw 'temporary builder profile is still loaded' }
    if ($builderProfile) { $builderProfile | Remove-CimInstance }
}
$administrator = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }
if (-not $administrator) { throw 'built-in Administrator account was not found' }
$replacementPassword = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'))
& net.exe user $administrator.Name $replacementPassword | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'built-in Administrator password rotation failed' }
Disable-LocalUser -Name $administrator.Name
$replacementPassword = $null

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($name in @('AutoAdminLogon', 'DefaultUserName', 'DefaultPassword', 'AutoLogonCount')) {
    Remove-ItemProperty -Path $winlogon -Name $name -ErrorAction SilentlyContinue
}

$sensitiveFiles = @(
    "$env:WINDIR\Panther\Unattend.xml",
    "$env:WINDIR\Panther\unattend\Unattend.xml",
    "$env:WINDIR\Panther\setupact.log",
    "$env:WINDIR\Panther\setuperr.log",
    "$env:WINDIR\Panther\UnattendGC\setupact.log",
    "$env:WINDIR\Panther\UnattendGC\setuperr.log"
)
foreach ($file in $sensitiveFiles) { Remove-SensitiveFile $file }
Get-ChildItem "$env:SystemDrive\Users" -Filter 'ConsoleHost_history.txt' -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { Remove-SensitiveFile $_.FullName }
Clear-EventLog -LogName 'Windows PowerShell' -ErrorAction SilentlyContinue

$cloudbase = Join-Path $env:ProgramFiles 'Cloudbase Solutions\Cloudbase-Init'
$unattend = Join-Path $cloudbase 'conf\Unattend.xml'
if (-not (Test-Path $unattend)) { throw 'Cloudbase-Init Sysprep answer file is missing' }
Set-Service -Name 'cloudbase-init' -StartupType Automatic

# Remove the uploaded copy containing the one-time secret immediately before Sysprep.
$self = $MyInvocation.MyCommand.Path
Unregister-ScheduledTask -TaskName 'HoneyForgeImageFinalize' -Confirm:$false -ErrorAction SilentlyContinue
Remove-SensitiveFile $self
& "$env:WINDIR\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /quiet /unattend:$unattend
if ($LASTEXITCODE -ne 0) { throw "Sysprep failed: $LASTEXITCODE" }
