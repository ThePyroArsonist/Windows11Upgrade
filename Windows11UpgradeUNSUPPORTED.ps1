# Variables
$isoUrl = "https://repo.mooit.com/files/Win11_24H2_English_x64.iso"  # Update to latest ISO URL as needed
$isoLocalPath = "C:\Temp\Win11.iso"
$localSetupPath = "C:\Temp\Win11Setup"
$localLogPath = "C:\Windows\Temp"
$setupExePath = Join-Path $localSetupPath "setup.exe"
$ScanXml = "$localLogPath\WindowsLog\Panther\ScanResult.xml"


function Write-Log {
<#
.SYNOPSIS
	Outputs Time, message type and message in patterned format. Also allows for logging to file with flags

.PARAMETER IncludeSeconds (-IncludeSeconds Flag)
	If set will include seconds in the timestamp
	Example: Write-Log Warning "Driver package looks incompatible" -IncludeSeconds
	Output: [15:30:59][Warning] "Driver package looks incompatible"

.PARAMETER FilePath (-FilePath Flag) 
	If set, output will be logged to a file as well as output to the console
	Example: Write-Log Error "Upgrade failed for device $deviceId" -FilePath "C:\Logs\upgrade.log"

.EXAMPLES
	# Simple
	#Write-Log Info "Starting upgrade on" $env:COMPUTERNAME

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet('Debug','Info','Warning','Error')]
        [string]$Level,

        [Parameter(Mandatory=$true, Position=1, ValueFromRemainingArguments=$true)]
        [string[]]$Message,

        [switch]$IncludeSeconds,

        [string]$FilePath   # optional: if supplied, append the plain text log line to this file
    )

    # timestamp format
    $tsFormat = if ($IncludeSeconds) { 'HH:mm:ss' } else { 'HH:mm' }
    $timestamp = (Get-Date).ToString($tsFormat)

    # join message array into single string
    $text = ($Message -join ' ')

    # choose color
    switch ($Level) {
        'Debug'   { $color = 'Gray' }
        'Info'    { $color = 'Green' }
        'Warning' { $color = 'Yellow' }
        'Error'   { $color = 'Red' }
        default   { $color = 'White' }
    }

    # format line example: [15:30][Info] - message
    $levelTag = "[{0}]" -f $Level
    $line = "[{0}]{1} - {2}" -f $timestamp, $levelTag, $text

    # console output (colored)
    Write-Host $line -ForegroundColor $color

    # optional: append plain text to file (no color codes)
    if ($PSBoundParameters.ContainsKey('FilePath') -and $FilePath) {
        try {
            $line | Out-File -FilePath $FilePath -Append -Encoding UTF8
        } catch {
            Write-Host "[{0}][Error] - Failed to write log file: {1}" -f (Get-Date -Format $tsFormat), $_.Exception.Message -ForegroundColor Red
        }
    }
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log Error "Please run this script as Administrator."
    exit 1
}

# Function: Finds unsigned Binaries/Software + Flag to uninstall
function Find-AndMapUnsignedDrivers {
<#
.SYNOPSIS
    Parse ScanResult.xml from Windows Setup/Upgrade to find blocking oem*.inf drivers,
    map them to installed devices/software, and optionally remove them.

.DESCRIPTION
    - Scans the ScanResult.xml for oem*.inf entries marked as unsigned/BlockMigration.
    - Maps INF to devices via Win32_PnPSignedDriver.
    - Attempts to find candidate installed software that provided the driver.
    - Outputs CSV and table of results.
    - Can optionally uninstall software and/or remove driver packages.

.PARAMETER ScanXml (-ScanXml flag)
    Path to the ScanResult.xml file.

.PARAMETER OutCsv (-OutCsv flag)
    Path to save the resulting CSV (default: .\driver_map.csv).

.PARAMETER DoRemoveDrivers (-DoRemoveDrivers flag)
    If set, will run pnputil /delete-driver oemX.inf /force on the blocking drivers.

.PARAMETER DoUninstallSoftware (-DoUninstallSoftware flag)
    If set, will execute uninstall strings found in the registry for candidate software.

.PARAMETER VerboseLog (-VerboseLog flag)
    If set, prints verbose log messages.

.RETURN
	Returns $true if unsigned drivers/software are found
	Returns $false if no unsigned drivers/software are found

.EXAMPLE
    Find-AndMapUnsignedDrivers -ScanXml .\ScanResult.xml -OutCsv .\drivers.csv -VerboseLog
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$ScanXml,
        # Export only if caller supplies a path; default $null avoids always exporting.
        [string]$OutCsv = $null,
        [switch]$DoRemoveDrivers,
        [switch]$DoUninstallSoftware,
        [switch]$VerboseLog,
        # If set, function will return the results objects instead of just a boolean
        [switch]$ReturnResults
    )

    function VerboseOut { if ($VerboseLog) { Write-Host $args -ForegroundColor Cyan } }

    # Helper to find candidate installed software by searching registry uninstall keys
    function Find-CandidateSoftware {
        param([string[]]$searchTokens)
        $candidates = @()
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($rp in $regPaths) {
            if (-not (Test-Path $rp)) { continue }
            Get-ChildItem $rp | ForEach-Object {
                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($null -eq $props) { return }
                $combined = "$($props.DisplayName) $($props.Publisher) $($props.InstallLocation) $($props.DisplayVersion)"
                foreach ($t in $searchTokens) {
                    if ($t -and $combined -and $combined.ToLower().Contains($t.ToLower())) {
                        $candidates += [PSCustomObject]@{
                            DisplayName     = $props.DisplayName
                            Publisher       = $props.Publisher
                            InstallLocation = $props.InstallLocation
                            UninstallString = $props.UninstallString
                        }
                        break
                    }
                }
            }
        }
        return $candidates | Select-Object -Unique
    }

    # --- Main logic ---

    if (-not (Test-Path $ScanXml)) { throw "ScanResult xml not found: $ScanXml" }
    [xml]$doc = Get-Content -Path $ScanXml -Raw

    # --- Find oem*.inf entries (namespace-agnostic + attribute-aware) ---
    $infs = @()

    # 1) Get all DriverPackage nodes regardless of namespace
    $driverPackageNodes = $doc.SelectNodes("//*[local-name()='DriverPackage']") 2>$null
    Write-Log Debug "DriverPackage nodes found: $($driverPackageNodes.Count -as [int])"

    if ($driverPackageNodes.Count -gt 0) {
        foreach ($n in $driverPackageNodes) {
            # Try canonical attribute names used in ScanResult.xml
            $infAttr = $n.GetAttribute("Inf")
            if (-not $infAttr) { $infAttr = $n.GetAttribute("InfName") }   # defensive fallback
            if (-not $infAttr) { continue }

            $infAttr = $infAttr.Trim()
            # Read attributes that indicate a blocking/unsigned driver
            $blockMigration = $n.GetAttribute("BlockMigration")
            $hasSigned = $n.GetAttribute("HasSignedBinaries")

            # Consider it a candidate if it's explicitly blocking OR explicitly unsigned
            $isBlock = $false
            if ($blockMigration) { $isBlock = $blockMigration.ToString().ToLower() -eq 'true' }
            if (-not $isBlock -and $hasSigned) { $isBlock = $hasSigned.ToString().ToLower() -eq 'false' }

            # If it looks like an oem INF and matches our blocking/unsigned criteria, capture it
            if ($infAttr -match "(oem\d+\.inf)") {
                if ($isBlock) {
                    $infs += $matches[1].ToLower()
                }
            }
        }
    }

    # 2) Secondary fallback: search *all* attributes in the document for oem*.inf (helps catch other formats)
    if ($infs.Count -eq 0) {
        $attrs = $doc.SelectNodes("//@*") 2>$null
        foreach ($a in $attrs) {
            if ($a.Value -match "(oem\d+\.inf)") { $infs += $matches[1].ToLower() }
        }
    }

    # de-duplicate & final check
    $infs = $infs | Select-Object -Unique

    if (-not $infs -or $infs.Count -eq 0) {
        Write-Log Warning "No oem*.inf entries found in $ScanXml"
        return $false
    }

    Write-Log Info "Found infs: $($infs -join ', ')"

    $results = @()

	# To find possible software using unsigned drivers + populate driver info
	foreach ($inf in $infs) {
		Write-Log Debug "Processing $inf"
		$drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
				   Where-Object { $_.InfName -and ($_.InfName.ToLower() -eq $inf.ToLower()) }

		if (-not $drivers) {
			# Try pnputil fallback and INF parsing
			$foundByPnP = $false
			$pnputilOutput = pnputil /enum-drivers 2>$null
			if ($pnputilOutput) {
				$blocks = ($pnputilOutput -join "`n") -split "Published Name"
				foreach ($b in $blocks) {
					if ($b -match "(oem\d+\.inf)" -and $matches[1].ToLower() -eq $inf.ToLower()) {
						$provider = ($b -split "`n" | Where-Object {$_ -match "Driver Provider"}) -replace ".*:\s*",""
						$version  = ($b -split "`n" | Where-Object {$_ -match "Driver Version"}) -replace ".*:\s*",""

						# Parse .INF file directly
						$infFile = Join-Path "C:\Windows\INF" $inf
						$manufacturer = $null; $class = $null; $serviceBinary = $null; $svcImagePath = $null
						if (Test-Path $infFile) {
							$infContent = Get-Content $infFile -ErrorAction SilentlyContinue
							$providerInf = $infContent | Select-String -Pattern "Provider" -SimpleMatch
							if ($providerInf) { $provider = ($providerInf -split "=")[-1].Trim() }
							$manu = $infContent | Select-String -Pattern "Manufacturer" -SimpleMatch
							if ($manu) { $manufacturer = ($manu -split "=")[-1].Trim() }
							$cls = $infContent | Select-String -Pattern "Class" -SimpleMatch
							if ($cls) { $class = ($cls -split "=")[-1].Trim() }
							$svc = $infContent | Select-String -Pattern "ServiceBinary" -SimpleMatch
							if ($svc) { $serviceBinary = ($svc -split "=")[-1].Trim() }
						}

						# Lookup service image path if possible
						if ($serviceBinary) {
							$svcKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -ErrorAction SilentlyContinue
							foreach ($k in $svcKeys) {
								try {
									$val = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).ImagePath
									if ($val -and $val.ToLower().Contains($serviceBinary.ToLower())) {
										$svcImagePath = $val
										break
									}
								} catch {}
							}
						}

						$results += [PSCustomObject]@{
							InfName           = $inf
							DeviceName        = "(Not bound to a device)"
							DeviceID          = $null
							Provider          = ($provider -join ' ').Trim()
							Manufacturer      = $manufacturer
							Class             = $class
							DriverVersion     = $version
							DriverFiles       = $null
							ServiceBinary     = $serviceBinary
							ServiceImagePath  = $svcImagePath
							CandidateSoftware = $null
						}
						$foundByPnP = $true
					}
				}
			}

			if (-not $foundByPnP) {
				$results += [PSCustomObject]@{
					InfName           = $inf
					DeviceName        = $null
					DeviceID          = $null
					Provider          = $null
					Manufacturer      = $null
					Class             = $null
					DriverVersion     = $null
					DriverFiles       = $null
					ServiceBinary     = $null
					ServiceImagePath  = $null
					CandidateSoftware = $null
				}
			}
			continue
		}

		foreach ($d in $drivers) {
			$searchTokens = @($d.DriverProviderName, $d.Manufacturer, $d.DeviceName) | Where-Object { $_ }
			$candidates = Find-CandidateSoftware -searchTokens $searchTokens
			$cs = if ($candidates) { $candidates | ConvertTo-Json -Depth 3 } else { $null }

			$results += [PSCustomObject]@{
				InfName           = $inf
				DeviceName        = $d.DeviceName
				DeviceID          = $d.DeviceID
				Provider          = $d.DriverProviderName
				Manufacturer      = $d.Manufacturer
				Class             = $d.ClassGuid
				DriverVersion     = $d.DriverVersion
				DriverFiles       = $d.InfName
				ServiceBinary     = $null
				ServiceImagePath  = $null
				CandidateSoftware = $cs
			}
		}

		# --- Hardened removal & verification logic (runs only if -DoRemoveDrivers is passed) ---
		if ($DoRemoveDrivers) {
			$infPath = Join-Path "$env:windir\INF" $inf
			if (-not (Test-Path $infPath)) {
				Write-Log Warning "$inf not found in $env:windir\INF — skipping removal"
				continue
			}

			Write-Log Debug "Attempting removal: pnputil /delete-driver $inf /uninstall /force"
			$output = pnputil /delete-driver $inf /uninstall /force 2>&1
			Write-Log Info $output

			if ($output -match "deleted successfully" -or $output -match "uninstalled successfully") {
				Write-Log Info "$inf removed successfully"
			} elseif ($output -match "in use" -or $output -match "cannot be deleted") {
				Write-Log Warning "$inf is still in use by a device; disable or uninstall device first."
			} else {
				Write-Log Warning "Failed to remove $inf. Output: $output"
			}

			# Post-removal verification
			Start-Sleep -Seconds 1
			if (Test-Path $infPath) {
				Write-Log Warning "$inf STILL PRESENT after attempted removal."
			} else {
				Write-Log Info "$inf successfully removed and no longer in INF folder."
			}
		}
	}

    # Export CSV only if caller supplied OutCsv
    if ($OutCsv) {
        try {
            $null = $results | Sort-Object InfName | Export-Csv -Path $OutCsv -NoTypeInformation -Force
            Write-Log Debug "Results exported to $OutCsv"
        } catch {
            Write-Log Warning "Failed to export CSV to $OutCsv : $_"
        }
    }

    # Optionally perform uninstall/remove steps (unchanged)
    if ($DoUninstallSoftware) {
        foreach ($r in $results) {
            if (-not $r.CandidateSoftware) { continue }
            $cands = $r.CandidateSoftware | ConvertFrom-Json
            foreach ($c in $cands) {
                if (-not $c.UninstallString) { Write-Warning "No uninstall string for $($c.DisplayName)"; continue }
                Write-Log Info "Attempting uninstall of $($c.DisplayName) using: $($c.UninstallString)"
                if ($c.UninstallString -match "msiexec") {
                    Start-Process -FilePath "msiexec.exe" -ArgumentList "/x",$c.UninstallString.Split()[-1],"/qn" -Wait -NoNewWindow
                } else {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c",$c.UninstallString -Wait
                }
            }
        }
    }

    if ($DoRemoveDrivers) {
        foreach ($inf in ($results | Select-Object -ExpandProperty InfName | Select-Object -Unique)) {
            Write-Log Debug "Deleting driver package: pnputil /delete-driver $inf /force"
            & pnputil /delete-driver $inf /force
        }
    }

    # If caller asked for objects, return them; otherwise return boolean
    if ($ReturnResults) {
        return $results
    } else {
        # After cleanup, recheck if any oem*.inf files still exist in DriverStore
        $remaining = @()
        foreach ($inf in ($results | Select-Object -ExpandProperty InfName | Select-Object -Unique)) {
            $driver = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                      Where-Object { $_.InfName -ieq $inf }
            if ($driver) { $remaining += $inf }
        }

        if ($remaining.Count -gt 0) {
            return $true   # still found after attempted cleanup
        } else {
            return $false  # nothing remains blocking upgrade
        }
    }
}

# Function: Compare file counts between source and destination
function Test-FolderIsComplete {
<#
.SYNOPSIS
    Test both Source and Destination files paths, compare Source and Destination files
	Copies Source files to Destination files if there are detected differences

.DESCRIPTION
    - Tests Source and Destination file paths
	- Compares all files in Source and Destination paths
	- Copies Source files to Destination if files are not the same
	
.PARAMETER Source (-Source flag)
    Path to the Source folder where the files being copied from
	
.PARAMETER Destination (-Destination flag)
    Path to the destination folder where the files are to be copied
	
.EXAMPLE
    Test-FolderIsComplete -Source $sourcePath -Destination $localSetupPath
#>
    param (
        [string]$Source,
        [string]$Destination
    )

    if (-not (Test-Path $Destination)) {
        return $false
    }

    try {
        $sourceFiles = Get-ChildItem -Path $Source -Recurse -File | Select-Object -ExpandProperty Name
        $destFiles = Get-ChildItem -Path $Destination -Recurse -File | Select-Object -ExpandProperty Name

        $missingFiles = $sourceFiles | Where-Object { $_ -notin $destFiles }

        return ($missingFiles.Count -eq 0)
    } catch {
        Write-Log Error "Error checking file completeness: $_"
        return $false
    }
}

# Function: Downloads + extracts ISO files
function SetupISOFiles {
<#
.SYNOPSIS
    Downloads Windows 11 ISO file from $isoUrl
	Mount ISO File and extract ISO files from $sourcePath to $localSetupPath

.DESCRIPTION
    - 
	
.EXAMPLE
    SetupISOFiles
#>	

	# Create Temp folder if it doesn't exist
	if (-not (Test-Path "C:\Temp")) {
		New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
	}

	# Download Windows 11 ISO if not already present
	if (-not (Test-Path $isoLocalPath)) {
		Write-Log Info "Downloading Windows 11 ISO from Microsoft..."
		try {
			Invoke-WebRequest -Uri $isoUrl -OutFile $isoLocalPath -UseBasicParsing -Verbose
		}
		catch {
			Write-Log Error "Failed to download Windows 11 ISO. $_"
			exit 1
		}
	} else {
		Write-Log Error "Windows 11 ISO already exists at $isoLocalPath"
	}

	# Mount the Windows 11 ISO
	Write-Log Info "Mounting the ISO..."
	try {
		$mountResult = Mount-DiskImage -ImagePath $isoLocalPath -PassThru
		# Wait for drive letter assignment
		Start-Sleep -Seconds 5
		$driveLetter = ($mountResult | Get-Volume).DriveLetter
		if (-not $driveLetter) {
			throw "Failed to get drive letter from mounted ISO."
		}
		$driveLetter += ":"
		Write-Log Info "ISO mounted at drive $driveLetter"
	}
	catch {
		Write-Log Error "Failed to mount ISO. $_"
		exit 1
	}
	Write-Log Info "Checking setup files in $localSetupPath..."

	$sourcePath = "$driveLetter\"
	$robocopyLog = "$env:TEMP\robocopy.log"

	# Only copy if folder is missing or incomplete
	if (-not (Test-FolderIsComplete -Source $sourcePath -Destination $localSetupPath)) {
		Write-Log Info "Setup files missing or incomplete. Copying to $localSetupPath..."

		# Remove old folder if exists
		if (Test-Path $localSetupPath) {
			try {
				Remove-Item -Path $localSetupPath -Recurse -Force
			} catch {
				Write-Log Error "Could not remove existing $localSetupPath. $_"
			}
		}

		# Create folder
		New-Item -Path $localSetupPath -ItemType Directory -Force | Out-Null

		# Run robocopy
		$robocopyResult = robocopy $sourcePath $localSetupPath /MIR /NFL /NDL /NJH /NJS /NP /LOG:$robocopyLog

		if ($LASTEXITCODE -ge 8) {
			Write-Log Error "Robocopy failed with exit code $LASTEXITCODE. Check log at $robocopyLog"
			# Dismount ISO before exit
			Dismount-DiskImage -ImagePath $isoLocalPath -ErrorAction SilentlyContinue
			exit 1
		} else {
			Write-Log Info "Files copied successfully to $localSetupPath"
		}
	} else {
		Write-Log Info "Setup files already present and complete in $localSetupPath. Skipping copy."
	}


	# Dismount the ISO
	try {
		Write-Log Info "Dismounting the ISO..."
		Dismount-DiskImage -ImagePath $isoLocalPath
	}
	catch {
		Write-Log Error "Failed to dismount ISO. You may need to do it manually."
	}
}

# Function: Installs Registry Bypass Keys
function SetupRegistryKeys {
<#
.SYNOPSIS
    Installs Windows 11 upgrade bypass keys
	Requires atleast TPM 1.2

.DESCRIPTION
    - 
	
.EXAMPLE
    SetupRegistryKeys
#>	

	# Set registry bypass keys
	# MoSetup is for inplace upgrades
	# LabConfig is for boot/clean install
	$regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\Setup\MoSetup"
	if (-not (Test-Path $regPath)) {
		New-Item -Path $regPath -Force | Out-Null
	}

	$regValues = @{
		"AllowUpgradesWithUnsupportedTPMOrCPU" = 1
		"BypassTPMCheck" = 1
		"BypassSecureBootCheck" = 1
		"BypassCPUCheck" = 1
		"BypassRAMCheck" = 1
	}

	# Add "BypassStorageCheck" = 1 if you want to bypass storage check

	foreach ($name in $regValues.Keys) {
		New-ItemProperty -Path $regPath -Name $name -PropertyType DWord -Value $regValues[$name] -Force | Out-Null
	}

	Write-Log Info "Registry bypass keys applied."
}

# Function: Sets up Cleanup script in RunOnce keys to remove upgrade setup files
function CleanupScript {
<#
.SYNOPSIS
    Defines CleanupPostUpgradeScript, installs script in RUNONCE registry keys
	Clears C:\Temp , C:\Windows.old
	Runs DISM CleanupComponent command to reset base image features
	Removes script from Registry keys on success

.DESCRIPTION
    - 
	
.EXAMPLE
    CleanupScript
#>	

	# Cleanup Script

	# Path for the post-upgrade script
	$PostUpgradeScriptPath = "C:\Windows\SystemTemp\CleanupUpgrade.ps1"

	# Check C:\Temp exists
	if (-not (Test-Path "C:\Temp")) {
		New-Item -ItemType Directory -Path "C:\Temp" | Out-Null
	}

	# Define CleanupPostUpgrade.ps1 script
	$cleanupScript = @'
	Start-Transcript -Path "C:\Windows\SystemTemp\CleanupUpgrade.log" -Append
	Write-Output "Starting post-upgrade cleanup..."

	# Clean C:\Temp
	try {
		if (Test-Path "C:\Temp") {
			Get-ChildItem -Path "C:\Temp" -Recurse -Force -ErrorAction SilentlyContinue |
			Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
			Write-Output "C:\Temp cleaned."
		} else {
			Write-Output "C:\Temp does not exist."
		}
	} catch {
		Write-Output "Error cleaning C:\Temp: $_"
	}

	# Delete Windows.old (if upgrade succeeded)
	try {
		if (Test-Path "C:\Windows.old") {
			Remove-Item -Path "C:\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue
			Write-Output "Windows.old removed."
		} else {
			Write-Output "No Windows.old found."
		}
	} catch {
		Write-Output "Error removing Windows.old: $_"
	}

	# Run DISM cleanup
	try {
		Write-Output "Running DISM cleanup..."
		Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
		Write-Output "DISM cleanup complete."
	} catch {
		Write-Output "DISM failed: $_"
	}

	# Remove this script from RunOnce
	try {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "PostUpgradeCleanup" -ErrorAction SilentlyContinue
		Write-Output "RunOnce key removed."
	} catch {
		Write-Output "Error removing RunOnce key: $_"
	}

	Stop-Transcript
'@

	# Save the script
	Set-Content -Path $PostUpgradeScriptPath -Value $cleanupScript -Encoding UTF8

	# Register the script to run once after next reboot
	New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
		-Name "PostUpgradeCleanup" `
		-Value "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PostUpgradeScriptPath`"" `
		-Force

	Write-Log Info "Post-upgrade cleanup script registered in RunOnce."
}

# Function: Runs setup.exe with arguments
function RunWindowsSetup {
<#
.SYNOPSIS
    Runs Microsoft setup.exe for windows inplace upgrade
	Logs saved to $localLogPath\WindowsLog
	Will attempt to install all missing updates
	On completion workstation does not restart

.DESCRIPTION
    - 
	
.EXAMPLE
    RunWindowsSetup
#>	

	# Check setup.exe path
	if (-not (Test-Path $setupExePath)) {
		Write-Log Error "setup.exe not found at $setupExePath"
		exit 1
	}

	Write-Log Info "Starting silent Windows 11 upgrade..."

	$arguments = "/auto upgrade /quiet /noreboot /dynamicupdate enable /telemetry disable /eula accept /showoobe none /compat IgnoreWarning /copylogs $localLogPath\WindowsLog"

	# Run setup.exe with Arguments
	try {
		Start-Process -FilePath $setupExePath -ArgumentList $arguments -Wait
		Write-Log Info "Upgrade process started successfully."
	}
	catch {
		Write-Log Error "Failed to start upgrade. $_"
		exit 1
	}
}

# ===========================================
# Main Logic
# ==========================================

# Download Windows Files
SetupISOFiles

# Install Bypass Registry Keys
SetupRegistryKeys

# Attempt Windows inplace upgrade
RunWindowsSetup

# Check is windows upgrade was successful
# -VerboseLog flag is keeping boolean from working correctly
# Manual Check
# Get-WindowsDriver -Online | Where-Object { $_.Driver -like "oem*.inf" } | Select-Object Driver, ProviderName, OriginalFileName, ClassName

# Returns True if unsigned drivers/software are found
# Returns False if no unsigned drivers/software is found
$found = Find-AndMapUnsignedDrivers -ScanXml $ScanXml -DoRemoveDrivers

# Attempt Windows inplace upgrade
#RunWindowsSetup

#Cleanup script then reboot?



'''
if($found){
    # Uninstall unsigned drivers and software
    Find-AndMapUnsignedDrivers -ScanXml $ScanXml -DoRemoveDrivers -DoUninstallSoftware
    #Rerun windows update
    RunWindowsSetup
	#Cleanup script
	CleanupScript
	#Reboot computer
    Restart-Computer -Force
} else {
	#Cleanup script
	CleanupScript
    #Reboot computer
    Restart-Computer -Force
}
'''