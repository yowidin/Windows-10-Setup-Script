#Requires -RunAsAdministrator
#Requires -Version 5

#region Preparation
Clear-Host

# Get information about the current culture settings
IF ($PSUICulture -eq "ru-RU")
{
	$RU = $true
}
# Detect the OS bitness
IF (-not ([Environment]::Is64BitOperatingSystem))
{
	IF ($RU)
	{
		Write-Host "The script supports Windows 10 x64 only" -BackgroundColor Red
	}
	else
	{
		Write-Host "Скрипт поддерживает только Windows 10 x64" -BackgroundColor Red
	}
	break
}
# Detect the PowerShell bitness
IF (-not ([IntPtr]::Size -eq 8))
{
	IF ($RU)
	{
		Write-Host "The script supports PowerShell x64 only" -BackgroundColor Red
	}
	else
	{
		Write-Host "Скрипт поддерживает только PowerShell x64" -BackgroundColor Red
	}
	break
}
#endregion Preparation

#region Begin
$Error.Clear()
# Set the encoding to UTF-8 without BOM for the PowerShell session
IF ($RU)
{
	ping.exe | Out-Null
	$OutputEncoding = [System.Console]::OutputEncoding = [System.Console]::InputEncoding = [System.Text.Encoding]::UTF8
}
#endregion Begin

#region Privacy & Telemetry
# Turn off "Connected User Experiences and Telemetry" service
Get-Service -Name DiagTrack | Stop-Service -Force
Get-Service -Name DiagTrack | Set-Service -StartupType Disabled
# Turn off per-user services
$services = @(
	# Contact Data
	"PimIndexMaintenanceSvc_*"
	# User Data Storage
	"UnistoreSvc_*"
	# User Data Access
	"UserDataSvc_*"
)
Get-Service -Name $services | Stop-Service -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UnistoreSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name Start -PropertyType DWord -Value 4 -Force
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\UserDataSvc -Name UserServiceFlags -PropertyType DWord -Value 0 -Force
# Stop event trace sessions
Get-EtwTraceSession -Name DiagLog -ErrorAction SilentlyContinue | Remove-EtwTraceSession
# Turn off the data collectors at the next computer restart
Update-AutologgerConfig -Name DiagLog, AutoLogger-Diagtrack-Listener -Start 0
# Set the operating system diagnostic data level
if ((Get-WindowsEdition -Online).Edition -eq "Enterprise" -or (Get-WindowsEdition -Online).Edition -eq "Education")
{
	# "Security"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force
}
else
{
	# "Basic"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force
}
# Turn off Windows Error Reporting
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Windows Error Reporting" -Name Disabled -PropertyType DWord -Value 1 -Force
# Change Windows Feedback frequency to "Never"
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Siuf\Rules))
{
	New-Item -Path HKCU:\Software\Microsoft\Siuf\Rules -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force
# Turn off diagnostics tracking scheduled tasks
$tasks = @(
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
	"Microsoft Compatibility Appraiser"
	# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program
	"ProgramDataUpdater"
	# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program
	"Proxy"
	# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
	"Consolidator"
	# The USB CEIP (Customer Experience Improvement Program) task collects Universal Serial Bus related statistics and information about your machine
	"UsbCeip"
	# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program
	"Microsoft-Windows-DiskDiagnosticDataCollector"
	# Protects user files from accidental loss by copying them to a backup location when the system is unattended
	"File History (maintenance mode)"
	# HelloFace
	"FODCleanupTask"
	# Measures a system's performance and capabilities
	"WinSAT"
	# This task shows various Map related toasts
	"MapsToastTask"
	# This task checks for updates to maps which you have downloaded for offline use
	"MapsUpdateTask"
	# Initializes Family Safety monitoring and enforcement
	"FamilySafetyMonitor"
	# Synchronizes the latest settings with the Microsoft family features service
	"FamilySafetyRefreshTask"
	# Windows Error Reporting task to process queued reports
	"QueueReporting"
	# XblGameSave Standby Task
	"XblGameSaveTask"
)
Get-ScheduledTask -TaskName $tasks | Disable-ScheduledTask
# Do not offer tailored experiences based on the diagnostic data setting
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy -Name TailoredExperiencesWithDiagnosticDataEnabled -PropertyType DWord -Value 0 -Force
# Do not let apps on other devices open and message apps on this device, and vice versa
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP -Name RomeSdkChannelUserAuthzPolicy -PropertyType DWord -Value 0 -Force
# Do not allow apps to use advertising ID
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -PropertyType DWord -Value 0 -Force
# Do not use sign-in info to automatically finish setting up device after an update or restart
$sid = (Get-CimInstance -ClassName Win32_UserAccount | Where-Object -FilterScript {$_.Name -eq "$env:USERNAME"}).SID
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$sid"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$sid" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$sid" -Name OptOut -PropertyType DWord -Value 1 -Force
# Do not let websites provide locally relevant content by accessing language list
New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name HttpAcceptLanguageOptOut -PropertyType DWord -Value 1 -Force
# Turn on tip, trick, and suggestions as you use Windows
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 1 -Force
# Do not show app suggestions on Start menu
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338388Enabled -PropertyType DWord -Value 0 -Force
# Do not show suggested content in the Settings
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force
# Turn off automatic installing suggested apps
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force
# Let track app launches to improve Start menu and search results
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Start_TrackProgs -PropertyType DWord -Value 1 -Force
#endregion Privacy & Telemetry

#region UI & Personalization
# Show "This PC" on Desktop
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value 0 -Force
# Set File Explorer to open to This PC by default
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force
# Show Hidden Files, Folders, and Drives
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -PropertyType DWord -Value 1 -Force
# Turn off check boxes to select items
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 0 -Force
# Show file name extensions
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force
# Show folder merge conflicts
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideMergeConflicts -PropertyType DWord -Value 0 -Force
# Do not show all folders in the navigation pane
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -PropertyType DWord -Value 0 -Force
# Do not show Cortana button on taskbar
IF (-not $RU)
{
	New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowCortanaButton -PropertyType DWord -Value 0 -Force
}
# Do not show Task View button on taskbar
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
# Do not show People button on the taskbar
IF (-not (Test-Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People -Name PeopleBand -PropertyType DWord -Value 0 -Force
# Show more details in file transfer dialog
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
# Turn on recycle bin files delete confirmation
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name ConfirmFileDelete -PropertyType DWord -Value 1 -Force
# Remove 3D Objects folder in "This PC" and in the navigation pane
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name ThisPCPolicy -PropertyType String -Value Hide -Force
# Do not show "Frequent folders" in Quick access
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowFrequent -PropertyType DWord -Value 0 -Force
# Do not show "Recent files" in Quick access
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ShowRecent -PropertyType DWord -Value 0 -Force
# Remove the "Previous Versions" tab from properties context menu
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name NoPreviousVersionsPage -PropertyType DWord -Value 1 -Force
# Hide search box or search icon on taskbar
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Search -Name SearchboxTaskbarMode -PropertyType DWord -Value 0 -Force
# Do not show "Windows Ink Workspace" button in taskbar
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace -Name PenWorkspaceButtonDesiredVisibility -PropertyType DWord -Value 0 -Force
# Always show all icons in the notification area
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name EnableAutoTray -PropertyType DWord -Value 0 -Force
# Unpin Microsoft Edge and Microsoft Store from taskbar
$Signature = @{
	Namespace = "WinAPI"
	Name = "GetStr"
	Language = "CSharp"
	MemberDefinition = @"
		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr GetModuleHandle(string lpModuleName);
		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		internal static extern int LoadString(IntPtr hInstance, uint uID, StringBuilder lpBuffer, int nBufferMax);
		public static string GetString(uint strId)
		{
			IntPtr intPtr = GetModuleHandle("shell32.dll");
			StringBuilder sb = new StringBuilder(255);
			LoadString(intPtr, strId, sb, sb.Capacity);
			return sb.ToString();
		}
"@
}
IF (-not ("WinAPI.GetStr" -as [type]))
{
	Add-Type @Signature -Using System.Text
}
$unpin = [WinAPI.GetStr]::GetString(5387)
$apps = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
$apps | Where-Object -FilterScript {$_.Path -like "Microsoft.MicrosoftEdge*"} | ForEach-Object -Process {$_.Verbs() | Where-Object -FilterScript {$_.Name -eq $unpin} | ForEach-Object -Process {$_.DoIt()}}
$apps | Where-Object -FilterScript {$_.Path -like "Microsoft.WindowsStore*"} | ForEach-Object -Process {$_.Verbs() | Where-Object -FilterScript {$_.Name -eq $unpin} | ForEach-Object -Process {$_.DoIt()}}
# Do not show "New App Installed" notification
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoNewAppAlert -PropertyType DWord -Value 1 -Force
# Turn off JPEG desktop wallpaper import quality reduction
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force
# Show Task Manager details
$taskmgr = Get-Process -Name Taskmgr -ErrorAction SilentlyContinue
IF ($taskmgr)
{
	$taskmgr.CloseMainWindow()
}
Start-Process -FilePath Taskmgr.exe -WindowStyle Hidden -PassThru
Do
{
	Start-Sleep -Milliseconds 100
	$preferences = Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -ErrorAction SilentlyContinue
}
Until ($preferences)
Stop-Process -Name Taskmgr
$preferences.Preferences[28] = 0
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $preferences.Preferences -Force
$Error.RemoveRange(0, $Error.Count)
# Remove Microsoft Edge shortcut from the Desktop
$value = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop
Remove-Item -Path "$value\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
# Turn off automatically hiding scroll bars
# Отключить автоматическое скрытие полос прокрутки в Windows
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name DynamicScrollbars -PropertyType DWord -Value 0 -Force
# Show more Windows Update restart notifications about restarting
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 1 -Force


#region System
# Delete temporary files that apps aren't using
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
# Never delete files in "Downloads" folder
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 512 -PropertyType DWord -Value 0 -Force
# Let Windows try to fix apps so they're not blurry
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name EnablePerProcessSystemDPI -PropertyType DWord -Value 1 -Force
# Turn off location for this device
# Отключить местоположение для этого устройства
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location -Name Value -PropertyType String -Value Deny -Force
# Change $env:TEMP environment variable path to $env:SystemDrive\Temp
# Изменить путь переменной среды для временных файлов на $env:SystemDrive\Temp
IF (-not (Test-Path -Path $env:SystemDrive\Temp))
{
	New-Item -Path $env:SystemDrive\Temp -ItemType Directory -Force
}
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "User")
New-ItemProperty -Path HKCU:\Environment -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Machine")
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name TEMP -PropertyType ExpandString -Value %SystemDrive%\Temp -Force
[Environment]::SetEnvironmentVariable("TMP", "$env:SystemDrive\Temp", "Process")
[Environment]::SetEnvironmentVariable("TEMP", "$env:SystemDrive\Temp", "Process")
Remove-Item $env:LOCALAPPDATA\Temp -Recurse -Force -ErrorAction SilentlyContinue
Restart-Service -Name Spooler -Force
Remove-Item -Path $env:SystemRoot\Temp -Recurse -Force -ErrorAction SilentlyContinue
# Group svchost.exe processes
$ram = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1kb
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value $ram -Force
# Display the Stop error information on the BSoD
New-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\CrashControl -Name DisplayParameters -PropertyType DWord -Value 1 -Force
# Do not preserve zone information
IF (-not (Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments))
{
	New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
}
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
# Turn off Delivery Optimization
Get-Service -Name DoSvc | Stop-Service -Force
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization -Name DODownloadMode -PropertyType DWord -Value 0 -Force
# Turn off Windows features
$features = @(
	# Work Folders Client
	"WorkFolders-Client"
)
Disable-WindowsOptionalFeature -Online -FeatureName $features -NoRestart
# Remove Windows capabilities
$IncludedApps = @(
	# Microsoft Quick Assist
	"App.Support.QuickAssist*"
	# Windows Hello Face
	"Hello.Face*"
	# Windows Media Player
	"Media.WindowsMediaPlayer*"
)
$OFS = "|"
Get-WindowsCapability -Online | Where-Object -FilterScript {$_.Name -cmatch $IncludedApps} | Remove-WindowsCapability -Online
$OFS = " "
# Turn off default background apps, except the followings...
$ExcludedApps = @(
	# Lock App
	"Microsoft.LockApp*"
	# Content Delivery Manager
	"Microsoft.Windows.ContentDeliveryManager*"
	# Cortana
	"Microsoft.Windows.Cortana*"
	# Windows Security
	# Безопасность Windows
	"Microsoft.Windows.SecHealthUI*"
	# ShellExperienceHost
	"Microsoft.Windows.ShellExperienceHost*"
	# StartMenuExperienceHost
	"Microsoft.Windows.StartMenuExperienceHost*"
)
$OFS = "|"
Get-ChildItem -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | Where-Object -FilterScript {$_.PSChildName -cnotmatch $ExcludedApps} |
ForEach-Object -Process {
	New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
}
$OFS = " "
# Set the default input method to the English language
Set-WinDefaultInputMethodOverride "0409:00000409"
# Turn on Windows Sandbox
IF (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -eq "Professional" -or $_.Edition -eq "Enterprise"})
{
	IF ((Get-CimInstance -ClassName CIM_Processor).VirtualizationFirmwareEnabled -eq $true)
	{
		Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart
	}
	else
	{
		try
		{
			IF ((Get-CimInstance -ClassName CIM_ComputerSystem).HypervisorPresent -eq $true)
			{
				Enable-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -All -Online -NoRestart
			}
		}
		catch
		{
			Write-Error "Enable Virtualization in BIOS"
		}
	}
}


# Turn on automatic backup the system registry to the $env:SystemRoot\System32\config\RegBack folder
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name EnablePeriodicBackup -PropertyType DWord -Value 1 -Force
# Turn off "The Windows Filtering Platform has blocked a connection" message in "Windows Logs/Security"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable
# Turn off SmartScreen for apps and files
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
# Turn off F1 Help key
IF (-not (Test-Path -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64"))
{
	New-Item -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Typelib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(default)" -PropertyType String -Value "" -Force
# Turn on Num Lock at startup
New-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard" -Name InitialKeyboardIndicators -PropertyType String -Value 2147483650 -Force
# Turn off sticky Shift key after pressing 5 times
New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force
# Turn off AutoPlay for all media and devices
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Name DisableAutoplay -PropertyType DWord -Value 1 -Force
# Turn off thumbnail cache removal
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" -Name Autorun -PropertyType DWord -Value 0 -Force
# Turn on automatically save my restartable apps when sign out and restart them after sign in
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -Value 1 -Force
# Include command line in progress creation events
New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force
#endregion System

#region Start menu
# Add old style shortcut for "Devices and Printers" to the Start menu
$target = "control"
$linkname = (Get-ControlPanelItem | Where-Object -FilterScript {$_.CanonicalName -eq "Microsoft.DevicesAndPrinters"}).Name
$link = "$env:APPDATA\Microsoft\Windows\Start menu\Programs\System Tools\$linkname.lnk"
$shell = New-Object -ComObject Wscript.Shell
$shortcut = $shell.CreateShortcut($link)
$shortcut.TargetPath = $target
$shortcut.Arguments = "printers"
$shortCut.IconLocation = "$env:SystemRoot\system32\DeviceCenter.dll"
$shortcut.Save()

# Restart Start menu
Stop-Process -Name StartMenuExperienceHost -Force
#endregion Start menu

#region Edge
# Turn off Windows Defender SmartScreen for Microsoft Edge
$edge = (Get-AppxPackage "Microsoft.MicrosoftEdge").PackageFamilyName
IF (-not (Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"))
{
	New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Force
}
New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name EnabledV9 -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter" -Name PreventOverride -PropertyType DWord -Value 0 -Force
# Do not allow Microsoft Edge to start and load the Start and New Tab page at Windows startup and each time Microsoft Edge is closed
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader -Name AllowTabPreloading -PropertyType DWord -Value 0 -Force
# Do not allow Microsoft Edge to pre-launch at Windows startup, when the system is idle, and each time Microsoft Edge is closed
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main -Name AllowPrelaunch -PropertyType DWord -Value 0 -Force
# Turn off creation of an Edge shortcut on the desktop for each user profile
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name DisableEdgeDesktopShortcutCreation -PropertyType DWord -Value 1 -Force
#endregion Edge

#region UWP apps
# Uninstall all UWP apps from all accounts, except the followings...
# Удалить все UWP-приложения из всех учетных записей, кроме следующих...
$ExcludedApps = @(
	# iTunes
	"AppleInc.iTunes"
	# Intel UWP-panel
	# UWP-панель Intel
	"AppUp.IntelGraphicsControlPanel"
	"AppUp.IntelGraphicsExperience"
	# Microsoft Desktop App Installer
	"Microsoft.DesktopAppInstaller"
	# Microsoft Store
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
	# Web Media Extensions
	# Расширения для интернет-мультимедиа
	"Microsoft.WebMediaExtensions"
	# Photos and Video Editor
	# Фотографии и Видеоредактор
	"Microsoft.Windows.Photos"
	# Calculator
	# Калькулятор
	"Microsoft.WindowsCalculator"
	# NVIDIA Control Panel
	"NVIDIACorp.NVIDIAControlPanel"
)
$OFS = "|"
Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object {$_.Name -cnotmatch $ExcludedApps} | Remove-AppxPackage -AllUsers
$OFS = " "
# Uninstall all provisioned UWP apps from System account, except the followings...
# App packages will not be installed when new user accounts are created
$ExcludedApps = @(
	# Intel UWP-panel
	# UWP-панель Intel
	"AppUp.IntelGraphicsControlPanel"
	"AppUp.IntelGraphicsExperience"
	# Microsoft Desktop App Installer
	"Microsoft.DesktopAppInstaller"
	# HEIF Image Extensions
	# Расширения для изображений HEIF
	"Microsoft.HEIFImageExtension"
	# Microsoft Store
	"Microsoft.StorePurchaseApp"
	"Microsoft.WindowsStore"
	# VP9 Video Extensions
	# Расширения для VP9-видео
	"Microsoft.VP9VideoExtensions"
	# Web Media Extensions
	# Расширения для интернет-мультимедиа
	"Microsoft.WebMediaExtensions"
	# WebP Image Extension
	# Расширения для изображений WebP
	"Microsoft.WebpImageExtension"
	# Photos and Video Editor
	# Фотографии и Видеоредактор
	"Microsoft.Windows.Photos"
	# Calculator
	# Калькулятор
	"Microsoft.WindowsCalculator"
	# NVIDIA Control Panel
	# Панель управления NVidia
	"NVIDIACorp.NVIDIAControlPanel"
)
$OFS = "|"
Get-AppxProvisionedPackage -Online | Where-Object -FilterScript {$_.DisplayName -cnotmatch $ExcludedApps} | Remove-AppxProvisionedPackage -Online
$OFS = " "
#endregion UWP apps

#region Windows Game Recording
# Turn off Windows Game Recording and Broadcasting
IF (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR))
{
	New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR -Force
}
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR -Name AllowgameDVR -PropertyType DWord -Value 0 -Force
# Turn off Game Bar
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -PropertyType DWord -Value 0 -Force
# Turn off Game Bar tips
New-ItemProperty -Path HKCU:\Software\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force
#endregion Windows Game Recording

#region Scheduled tasks
# Create a task in the Task Scheduler to start Windows cleaning up
# The task runs every 90 days
$keys = @(
	# Delivery Optimization Files
	"Delivery Optimization Files",
	# Device driver packages
	"Device Driver Packages",
	# Previous Windows Installation(s)
	"Previous Installations",
	"Setup Log Files",
	# Temporary Setup Files
	"Temporary Setup Files",
	# Windows Update Cleanup
	"Update Cleanup",
	# Windows Defender Antivirus
	"Windows Defender",
	# Windows upgrade log files
	"Windows Upgrade Log Files"
)
foreach ($key in $keys)
{
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$key" -Name StateFlags1337 -PropertyType DWord -Value 2 -Force
}
$action = New-ScheduledTaskAction -Execute "cleanmgr.exe" -Argument "/sagerun:1337"
$trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 90 -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$params = @{
	"TaskName"	=	"Update Cleanup"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
# Create a task in the Task Scheduler to clear the $env:SystemRoot\SoftwareDistribution\Download folder
# The task runs on Thursdays every 4 weeks
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument @"
	`$getservice = Get-Service -Name wuauserv
	`$getservice.WaitForStatus("Stopped", "01:00:00")
	Get-ChildItem -Path `$env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
"@
$trigger = New-JobTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Thursday -At 9am
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
$params = @{
	"TaskName"	=	"SoftwareDistribution"
	"Action"	=	$action
	"Trigger"	=	$trigger
	"Settings"	=	$settings
	"Principal"	=	$principal
}
Register-ScheduledTask @params -Force
#endregion Scheduled tasks

#region Microsoft Defender

# Turn on Windows Defender Sandbox
setx /M MP_FORCE_USE_SANDBOX 1
# Hide notification about sign in with Microsoft in the Windows Security
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AccountProtection_MicrosoftAccount_Disconnected -PropertyType DWord -Value 1 -Force
# Hide notification about disabled SmartScreen for Microsoft Edge
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Name AppAndBrowser_EdgeSmartScreenOff -PropertyType DWord -Value 0 -Force
#endregion Microsoft Defender

#region Context menu
# Add "Extract" to MSI file type context menu
IF (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
}
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`"" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-31382" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force
# Add "Run as different user" from context menu for .exe file type
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name "(default)" -PropertyType String -Value "@shell32.dll,-50944" -Force
Remove-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name Extended -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser -Name SuppressionPolicyEx -PropertyType String -Value "{F211AA05-D4DF-4370-A2A0-9F19C09756A7}" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\exefile\shell\runasuser\command -Name DelegateExecute -PropertyType String -Value "{ea72d00e-4960-42fa-ba92-7792a7944c1d}" -Force
# Add "Install" to CAB file type context menu
IF (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command))
{
	New-Item -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Force
}
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command -Name "(default)" -PropertyType String -Value "cmd /c DISM /Online /Add-Package /PackagePath:`"%1`" /NoRestart & pause" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name MUIVerb -PropertyType String -Value "@shell32.dll,-10210" -Force
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs -Name HasLUAShield -PropertyType String -Value "" -Force
# Remove "Cast to Device" from context menu
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force
# Remove "Share" from context menu
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force
# Remove "Previous Versions" from file context menu
IF (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
{
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{596AB062-B4D2-4215-9F74-E9109B0A8153}" -PropertyType String -Value "" -Force
# Remove "Edit with Paint 3D" from context menu
$exts = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
foreach ($ext in $exts)
{
	New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$ext\Shell\3D Edit" -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
}
# Remove "Include in Library" from context menu
New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\Library Location" -Name "(default)" -PropertyType String -Value "-{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" -Force
# Remove "Create a new video" from context menu
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo -Name ProgrammaticAccessOnly -PropertyType String -Value "" -Force
# Remove "Send to" from folder context menu
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo -Name "(default)" -PropertyType String -Value "" -Force
# Turn off "Look for an app in the Microsoft Store" in "Open with" dialog
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force
#endregion Context menu

#region End
# Errors output
if ($Error)
{
	Write-Host "`nWarnings/Errors" -BackgroundColor Red
	($Error | ForEach-Object -Process {
		[PSCustomObject] @{
			Line = $_.InvocationInfo.ScriptLineNumber
			Error = $_.Exception.Message
		}
	} | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-String).Trim()
}
#endregion End
