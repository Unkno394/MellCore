$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$volume = Get-Volume -FileSystemLabel 'HFBUILDER'
if (-not $volume) { throw 'HFBUILDER payload CD is missing' }
$payload = "$($volume.DriveLetter):\"
$arguments = @(
    '/i', "$payload\CloudbaseInitSetup.msi", '/qn', '/norestart',
    'RUN_SERVICE_AS_LOCAL_SYSTEM=1', 'INJECTMETADATAPASSWORD=TRUE',
    'USERGROUPS=Administrators', 'LOGGINGSERIALPORTNAME=COM1',
    'SYSPREP=0', 'SYSPREPSHUTDOWN=0'
)
$process = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -notin @(0, 1641, 3010)) { throw "Cloudbase-Init installation failed: $($process.ExitCode)" }

$cloudbase = Join-Path $env:ProgramFiles 'Cloudbase Solutions\Cloudbase-Init'
$conf = Join-Path $cloudbase 'conf'
if (-not (Test-Path $conf)) { throw 'Cloudbase-Init configuration directory is missing' }

$metadataService = 'cloudbaseinit.metadata.services.configdrive.ConfigDriveService'
$plugins = @(
    'cloudbaseinit.plugins.common.mtu.MTUPlugin',
    'cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin',
    'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
    'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin',
    'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',
    'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin',
    'cloudbaseinit.plugins.common.userdata.UserDataPlugin',
    'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin',
    'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin'
) -join ','

@"
[DEFAULT]
username=hfadmin
groups=Administrators
inject_user_password=true
first_logon_behaviour=no
metadata_services=$metadataService
config_drive_cdrom=true
config_drive_raw_hhd=false
config_drive_vfat=false
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
allow_reboot=true
check_latest_version=false
plugins=$plugins
"@ | Set-Content -Path (Join-Path $conf 'cloudbase-init.conf') -Encoding ASCII

$unattendPlugins = @(
    'cloudbaseinit.plugins.common.mtu.MTUPlugin',
    'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
    'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin'
) -join ','
@"
[DEFAULT]
username=hfadmin
groups=Administrators
inject_user_password=true
metadata_services=$metadataService
config_drive_cdrom=true
config_drive_raw_hhd=false
config_drive_vfat=false
allow_reboot=false
check_latest_version=false
plugins=$unattendPlugins
"@ | Set-Content -Path (Join-Path $conf 'cloudbase-init-unattend.conf') -Encoding ASCII

Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

$service = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
if (-not $service) { throw 'Cloudbase-Init service was not installed' }
Set-Service -Name $service.Name -StartupType Automatic
Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue

$qga = Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
if (-not $qga) { throw 'QEMU Guest Agent service was not installed' }
Set-Service -Name $qga.Name -StartupType Automatic
