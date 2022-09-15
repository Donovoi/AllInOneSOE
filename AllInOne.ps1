function Set-PowerCFG {
    [CmdletBinding()]
    param (

    )
    Write-Verbose 'PowerSettings that will help you!'
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -monitor-timeout-dc 0
    powercfg /hibernate off
    powercfg -change standby-timeout-ac 0
    powercfg -change standby-timeout-dc 0
    powercfg -change disk-timeout-ac 0
    powercfg -change disk-timeout-dc 0
    powercfg -change hibernate-timeout-ac 0
    powercfg -change hibernate-timeout-dc 0
}

function Update-VcRedist {
    [CmdletBinding()]
    param(
        [string][Parameter(mandatory = $false)] $DownloadDirectory = "$ENV:USERPROFILE\Downloads"
    )

    begin {
        ##we need to install a few things before we install any modules
        Install-PackageProvider -Name NuGet -Force;
        Install-Module -Name VcRedist -Force;
        Import-Module -Name VcRedist;
        $VcFolder = New-Item -Path "$DownloadDirectory\VcRedist" -ItemType Directory -Force;
    }

    process {
        # Install VC++ Redis, if it fails then the install needs to stop so we can fix it
        try {
            Get-VcList | Save-VcRedist -Path $VcFolder;
            $VcList = Get-VcList;
            Install-VcRedist -VcList $VcList -Path $VcFolder;
        } catch {
            Write-Host $_;
            Write-Error 'There is a problem installing the required Visual Studio Redistributables' -ErrorAction Stop;
        }
    }

    end {
        #Sometimes VC++ 2013 is not installed via the above method - so ensuring it is installed
        Invoke-WebRequest -Uri 'http://download.microsoft.com/download/0/5/6/056dcda9-d667-4e27-8001-8a0c6971d6b1/vcredist_x64.exe' -Verbose -UseBasicParsing -OutFile "$DownloadDirectory\vc2013.exe";
        Start-Process -FilePath "$DownloadDirectory\vc2013.exe" -ArgumentList '/install /passive';

        Write-Host 'All Done!';
    }
}


function Install-ChocoBox {
    [CmdletBinding()]
    param (

        
    )        

    # Making sure Boxstarter can find chocolatey
    if (-not (Test-Path -Path "C:\ProgramData\Chocolatey")) {
        New-Item -Path "C:\ProgramData\Chocolatey" -Force
    }
    $ENV:ChocolateyInstall = "C:\ProgramData\Chocolatey\"

    # Install boxstarter to handle reboots
    Write-Verbose "Install boxstarter to handle reboots, this will install chocolatey as well"
    . { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | Invoke-Expression; Get-Boxstarter -Force
    #Just in case
    choco install boxstarter --force
    choco install boxstarter.winconfig --force
}

function Install-PackageManagers {
    [CmdletBinding()]
    param (
        # Install Chocolatey
        [Parameter(Mandatory = $false)]
        [switch]
        $InstallChocolatey,
        # Install Winget
        [Parameter(Mandatory = $false)]
        [switch]
        $InstallWinget
    )       
    
    # Install Chocolatey 
    Write-Verbose 'Installing Chocolatey'
    if (-not (Test-Path $Profile)) {
        New-Item $Profile -Force
    }        
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    $ENV:ChocolateyInstall = "C:\ProgramData\Chocolatey\"
    #Make sure have winget aswell
    if (-not (winget.exe | Select-String 'Windows Package Manager')) {
        Write-Verbose 'Installing winget'
        Install-WinGet -Verbose
    }


      

}

function Start-AsAdmin {
    [CmdletBinding()]
    param (
       
    )
    # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
    if (-not $isAdmin) {
        Write-Error "Please reopen powershell 5 and run as admin"
        exit
    }
}




function Set-SOE {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $NoPassword
    )

    begin {
        Start-AsAdmin -WindowsPowerShell
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Scope CurrentUser

        # Reset all group poilicies to system defaults
        cmd.exe /c "RD /S /Q %WinDir%\System32\GroupPolicyUsers && RD /S /Q %WinDir%\System32\GroupPolicy" -NoNewWindow -Wait
        gpupdate /force
        # Make sure we import all external modules needed
        Install-Module -ModuleName WingetTools
        if ($psversiontable.psversion.Major -gt 5) {
            Install-Module -Name WindowsCompatibility -Force -Verbose
        }
        
        if (-not (Test-Path $Profile)) {
            New-Item $Profile -Force
        }  
        $Global:parentpathprofile = $($(Resolve-Path -Path $Profile) -split 'Microsoft.PowerShell_profile.ps1')[0]
    }

    process {
        Write-Verbose "Setting Power to be always on"
        Set-PowerCFG -Verbose

        # They have a password get their creds
        if (-not ($NoPassword)) {
            $creds = Get-Credential -Credential $ENV:USERNAME -Verbose
        }

        Install-ChocoBox
        # Set boxstarter options
        # Boxstarter options
        $Boxstarter.RebootOk = $True # Allow reboots?
        $Boxstarter.NoPassword = $NoPassword # Is this a machine with no login password?
        $Boxstarter.AutoLogin = $True # Save my password securely and auto-login after a reboot

        if ($PSBoundParameters.ContainsKey('NoPassword')) {
            $Parameters = @{    
                PackageName = "https://gist.githubusercontent.com/Donovoi/6d7d5e6e1d80ba67040075c2cefa8875/raw/81ad20780d86090ca4a1cd6a83941e4002c2fd10/boxstarter-install.txt"
                Verbose     = $true
            }
            
        } else {
            $Parameters = @{    
                Credentials = $creds
                PackageName = "https://gist.githubusercontent.com/Donovoi/6d7d5e6e1d80ba67040075c2cefa8875/raw/81ad20780d86090ca4a1cd6a83941e4002c2fd10/boxstarter-install.txt"
                Verbose     = $true
            }
        }

        Install-BoxstarterPackage @Parameters
        # Make sure we have the latest Redistributables
        Write-Verbose 'Updating Redistributables'
        Update-VcRedist -Verbose
        Set-GroupPolicy -Verbose

        Install-PackageManagers

        # install the first round of apps we need
        Write-Verbose 'Installing first round of apps'
        choco install Microsoft-Hyper-V-All VirtualMachinePlatform HypervisorPlatform TFTP TIFFIFilter Microsoft-Windows-Subsystem-Linux Client-ProjFS NetFx4-AdvSrvs NetFx4Extended-ASPNET45 Containers-DisposableClientVM -source windowsFeatures
        Enable-PSRemoting -SkipNetworkProfileCheck -Force 
        Invoke-WebRequest -UseBasicParsing -Uri "https://gist.github.com/Donovoi/9589627f7e8e70bee3497549a88070dc/archive/4081e0375083db1a1ce6aab51acee0668b1b07cd.zip" -OutFile "$ENV:USERPROFILE\Downloads\PSPROFILE.zip"
        Expand-Archive -Path "$ENV:USERPROFILE\Downloads\PSPROFILE.zip" -DestinationPath "$ENV:USERPROFILE\Downloads\PSPROFILE" -Force
        Copy-Item -Path "$ENV:USERPROFILE\Downloads\PSPROFILE\*\*" -Destination $parentpathprofile -Force

        # Run sophia script to set up windows
        Write-Verbose 'Running sophia script to set up windows'
        Remove-Item -Path '.\Sophia Script for *\' -Recurse -Force
        Invoke-RestMethod script.sophi.app -UseBasicParsing | Invoke-Expression
        # Unblock all the things
        Write-Verbose 'Unblocking all the files everywhere'
        Get-ChildItem -Path *.* -Recurse -Force | Unblock-File
        #Load the functions from the downloaded script
        Write-Verbose 'Loading functions from downloaded script'
        . '.\Sophia Script for *\Functions.ps1'
        # Run the script with the functions that we are after
        Write-Verbose 'Running the script with the functions that we are after'
        Sophia -Functions 'Checkings -Warning', 'CreateRestorePoint', 'DiagTrackService -Enable', 'FeedbackFrequency -Automatically', 'LanguageListAccess -Disable', 'AdvertisingID -Disable', 'WindowsWelcomeExperience -Hide', 'WindowsTips -Disable', 'SettingsSuggestedContent -Hide', 'AppsSilentInstalling -Disable', 'WhatsNewInWindows -Disable', 'TailoredExperiences -Disable', 'BingSearch -Disable', 'ThisPC -Show', 'CheckBoxes -Disable', 'HiddenItems -Enable', 'FileExtensions -Show', 'MergeConflicts -Show', 'OpenFileExplorerTo -ThisPC', 'CortanaButton -Hide', 'OneDriveFileExplorerAd -Hide', 'FileTransferDialog -Detailed', 'FileExplorerRibbon -Expanded', 'RecycleBinDeleteConfirmation -Enable', '3DObjects -Hide', 'TaskbarSearch -Hide', 'TaskViewButton -Hide', 'SearchHighlights -Hide', 'PeopleTaskbar -Hide', 'SecondsInSystemClock -Show', 'WindowsInkWorkspace -Hide', 'NotificationAreaIcons -Show', 'MeetNow -Hide', 'NewsInterests -Disable', 'UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail', 'ControlPanelView -SmallIcons', 'WindowsColorMode -Dark', 'AppColorMode -Dark', 'NewAppInstalledNotification -Hide', 'FirstLogonAnimation -Disable', 'JPEGWallpapersQuality -Max', 'TaskManagerWindow -Expanded', 'RestartNotification -Show', 'PrtScnSnippingTool -Enable', 'OneDrive -Uninstall', 'StorageSense -Enable', 'StorageSenseFrequency -Month', 'StorageSenseTempFiles -Enable', 'Hibernation -Disable', 'Win32LongPathLimit -Disable', 'BSoDStopError -Enable', 'AdminApprovalMode -Never', 'MappedDrivesAppElevatedAccess -Enable', 'DeliveryOptimization -Enable', 'WaitNetworkStartup -Enable', 'WindowsManageDefaultPrinter -Disable', 'WindowsFeatures -Disable', 'WindowsFeatures -Enable', 'WindowsCapabilities -Uninstall', 'WindowsCapabilities -Install', 'UpdateMicrosoftProducts -Enable', 'PowerPlan -High', 'LatestInstalled.NET -Enable', 'NetworkAdaptersSavePower -Disable', 'InputMethod -English', 'WinPrtScrFolder -Desktop', 'RecommendedTroubleshooting -Automatically', 'FoldersLaunchSeparateProcess -Enable', 'ReservedStorage -Enable', 'F1HelpPage -Disable', 'NumLock -Enable', 'StickyShift -Disable', 'Autoplay -Disable', 'ThumbnailCacheRemoval -Disable', 'SaveRestartableApps -Enable', 'NetworkDiscovery -Enable', 'ActiveHours -Automatically', 'RestartDeviceAfterUpdate -Enable', 'UninstallPCHealthCheck', 'InstallVCRedistx64', 'InstallDotNetRuntime6', 'WSL', 'AppSuggestions -Hide', 'RunPowerShellShortcut -Elevated', 'PinToStart -Tiles ControlPanel, DevicesPrinters, PowerShell', 'UninstallUWPApps', 'RestoreUWPApps', 'HEIF -Install', 'CortanaAutostart -Disable', 'BackgroundUWPApps -Disable', 'CheckUWPAppsUpdates', 'XboxGameBar -Disable', 'XboxGameTips -Disable', 'SetAppGraphicsPerformance', 'GPUScheduling -Enable', 'CleanupTask -Register', 'SoftwareDistributionTask -Register', 'TempTask -Register', 'DismissMSAccount', 'DismissSmartScreenFilter', 'AuditProcess -Enable', 'EventViewerCustomView -Enable', 'PowerShellModulesLogging -Enable', 'PowerShellScriptsLogging -Enable', 'AppsSmartScreen -Disable', 'SaveZoneInformation -Disable', 'MSIExtractContext -Show', 'CABInstallContext -Show', 'RunAsDifferentUserContext -Show', 'CastToDeviceContext -Hide', 'ShareContext -Hide', 'EditWithPaint3DContext -Hide', 'EditWithPhotosContext -Hide', 'CreateANewVideoContext -Hide', 'PrintCMDContext -Hide', 'IncludeInLibraryContext -Hide', 'RichTextDocumentNewContext -Hide', 'CompressedFolderNewContext -Hide', 'MultipleInvokeContext -Enable', 'UseStoreOpenWith -Hide', 'UpdateLGPEPolicies', 'Errors', 'RefreshEnvironment' -verbose

    }
        
    end {
        # Chocolatey profile
        $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
        Import-Module $ChocolateyProfile
        RefreshEnv.cmd    
    }
}


