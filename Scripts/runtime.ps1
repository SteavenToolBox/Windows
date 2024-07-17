If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

function Install-Chocolatey {
	# Check if Chocolatey is installed
	if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
   	 # If not installed, install Chocolatey
   	 Write-Host "Chocolatey is not installed. Installing Chocolatey..."
    
  	  # Set execution policy and download/install Chocolatey
  	  Set-ExecutionPolicy Bypass -Scope Process -Force
 	   [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
 	   Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	   choco feature enable -n=allowGlobalConfirmation -y
	} else {
	    # If installed, display a message
	    Write-Host "Chocolatey is already installed. Run 'choco update' to get the latest version."
	}
	# Check if ChocolateyGUI is installed
	if (-not (Get-Command chocolateygui -ErrorAction SilentlyContinue)) {
   	 # If not installed, install ChocolateyGUI
   	 Write-Host "ChocolateyGUI is not installed. Installing ChocolateyGUI..."
   	 choco install chocolateygui -y
	} else {
   	 # If installed, display a message
   	 Write-Host "ChocolateyGUI is already installed."
	}
}

function Install-Winget {
    # GUI Specs
    Write-Host "Checking winget..."

    # Check if winget is installed
    if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
        'Winget Already Installed'
    }  
    else{
        # Installing winget using Chocolatey
        Write-Host "Winget not found, installing it now."
        $ResultText.text = "`r`n" + "`r`n" + "Installing Winget... Please Wait"
        choco install winget -y
        Write-Host Winget Installed
        $ResultText.text = "`r`n" + "`r`n" + "Winget Installed"
    }
}

function Install-Scoop {
	# Check if Scoop is installed
	if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
   	 # If not installed, install Scoop
 	   Write-Host "Scoop is not installed. Installing Scoop..."
 	   iex "& { $(irm get.scoop.sh) } -RunAsAdmin"
	} else {
 	   # If installed, display a message
 	   Write-Host "Scoop is already installed. Run 'scoop update' to get the latest version."
	}
    scoop install git
    scoop bucket add extras
    Write-Output "Scoop is now installed"
    scoop install aria2 wget git grep gsudo
    Write-Output "Aria2, Wget, and Git are now installed"
}
function Install-WindowsUpdateCli {
    # Store the current ConfirmPreference
    $currentConfirmPreference = $ConfirmPreference

    # Set the ConfirmPreference to "Yes" only for this function
    $ConfirmPreference = 'Yes'
    
    # Set PSGallery to Trusted
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    # Check if PSWindowsUpdate module is installed
    if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
    }

    # Check if WUServiceManager has Microsoft Update configured
    $wuService = Get-WUServiceManager
    if (-not ($wuService.MicrosoftUpdate -eq $true)) {
        Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
    }

    # Restore the original ConfirmPreference
    $ConfirmPreference = $currentConfirmPreference
}

function Install-Topgrade {
    Write-Host "Checking if Topgrade is installed..."
    try {
        topgrade --version | Out-String
        Write-Host "Topgrade is already installed."
    } catch {
        Write-Host "Topgrade is not installed. Attempting to install using winget..."
        winget install -e --id topgrade-rs.topgrade
        Write-Host "Topgrade installation complete."
    }
    
    # Edit the configuration file to enable winget regardless of installation status
    $configPath = Join-Path $env:APPDATA "topgrade.toml"
    if (Test-Path $configPath) {
        (Get-Content $configPath) -replace '# enable_winget = true', 'enable_winget = true' | Set-Content $configPath
        Write-Host "Updated topgrade.toml to enable winget."
    } else {
        Write-Host "Configuration file not found at $configPath"
    }
}

# Call the functions where needed
Install-Chocolatey
Install-Winget
Install-Scoop
Install-WindowsUpdateCli
Install-Topgrade
pause