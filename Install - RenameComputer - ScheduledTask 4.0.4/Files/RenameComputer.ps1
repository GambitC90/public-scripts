<#
Disclaimer:
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.

THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  

We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code,
provided that you agree: 
	(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
	(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
	(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys� fees, that arise or result from the use or distribution of the Sample Code.

Please note: None of the conditions outlined in the disclaimer above will supersede the terms and conditions contained within the Premier Customer Services Description.
#>

function RC_Test-Architecture {

	# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
	if (!([Environment]::Is64BitProcess)) {
		if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
			Stop-Transcript
			& "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy bypass -File "$PSCommandPath" -Prefix $Prefix
			Exit $lastexitcode
		}
	}
}

function RC_Initialize-Script {
	# Initialization
	RC_Initialize-ComputerObject

	if (-not (Test-Path $($RC_ComputerObject.ScratchSpace))) { mkdir $($RC_ComputerObject.ScratchSpace) }
	Start-Transcript "$($RC_ComputerObject.ScratchSpace)\RenameComputer.log"
}

function RC_Test-ComputerName {
	param (
		[String]$ComputerName
	)
	If ($($ComputerName.Length) -le 15) {
		If ($($ComputerName) -match "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$") {
			Write-Host "Computer Name [$ComputerName] meets requirements."
			Return $true
		} Else {
			Write-Host "Computer Name [$ComputerName] does not meets requirements."
			Return $false
		}
	} else {
		Write-Host "Computer Name [$ComputerName] > 15 Characters."
		Return $false
	}
}

function RC_Get-ChassisType {
	$Computer = Get-WmiObject -Class "Win32_SystemEnclosure"
	$tmpDeviceChassisType = "Unknown"
	switch ($Computer.ChassisTypes) {
		{ ($_ -eq "8") -or 
			($_ -eq "9") -or
			($_ -eq "10") -or
			($_ -eq "11") -or
			($_ -eq "12") -or
			($_ -eq "14") -or
			($_ -eq "18") -or
			($_ -eq "21") -or
			($_ -eq "30") -or
			($_ -eq "31") -or
			($_ -eq "32") } { $tmpDeviceChassisType = "Laptop" }
			
		{ ($_ -eq "3") -or 
			($_ -eq "4") -or
			($_ -eq "5") -or
			($_ -eq "6") -or
			($_ -eq "7") -or
			($_ -eq "13") -or
			($_ -eq "15") -or
			($_ -eq "16") -or
			($_ -eq "35") -or
			($_ -eq "36") } { $tmpDeviceChassisType = "Desktop" }
		{ ($_ -eq "23") -or 
			($_ -eq "28") } { $tmpDeviceChassisType = "Server" }
		Default { $tmpDeviceChassisType = "Unknown" }
	}
	Write-Host "Computer Chassis Type is [$tmpDeviceChassisType]."
	Return $tmpDeviceChassisType
}

function RC_Get-SerialNumber {
	param(
		[int]$LimitCharacters
	)
	$SerialNumber = $null
	# Get the new computer name: use the Serial Number 
	if ($null -ne $ComputerInformation.BiosSerialNumber) {
		$SerialNumber = $ComputerInformation.BiosSerialNumber
	} else {
		$SerialNumber = $ComputerInformation.BiosSeralNumber #This is for a bug in Windows PowerShell 5.1 - BiosSerialNumber was spelt wrong
	}

	$SerialNumber = $(RC_Remove-InvalidCharacters -InputText $SerialNumber)

	If (($null -ne $LimitCharacters) -and ($SerialNumber.Length -ge $LimitCharacters)) { $SerialNumber = $SerialNumber.Substring(0, $LimitCharacters) }

	Write-Host "Computer Serial Number is [$SerialNumber]."
	Return $SerialNumber

}

function RC_Remove-InvalidCharacters {
	param (
		[String]$InputText
	)
	Return ($InputText -replace "\\", "" -replace "/", ""	-replace ":", ""	-replace "\*", ""	-replace "\?", ""	-replace '"', ""	-replace ">", ""	-replace "<", ""	-replace "\|", "" -replace " ", "")
}

function RC_Convert-ChassisType {
	param (
		[string]$ChassisType = $(RC_Get-ChassisType)
	)
	$tmpChassisIdentifier = "D"
	switch ($ChassisType) {
		"Laptop" { $tmpChassisIdentifier = "N" }
		"Desktop" { $tmpChassisIdentifier = "D" }
		Default { $tmpChassisIdentifier = "D" }
	}
	Write-Host "Computer Chassis Type Identifyer is [$tmpChassisIdentifier]."
	Return $tmpChassisIdentifier
}

function RC_Generate-NewComputerName {
 #This funtion needs to be modified to meet requirements

	#Trigger File
	If ($null -eq $Generated_ComputerName) {

		$TriggerFile = Get-ChildItem -Path "$PSScriptRoot\*" -Include "*.tag"

		If ($TriggerFile) {
			If ($TriggerFile.Count -ne 1) {
				Write-Host "Miltiple .tag files found in [$PSScriptRoot] - please remove the extra ones."
			} else {
				Write-Host "Trigger File found in [$PSScriptRoot]."
				$Generated_ComputerName = $TriggerFile.BaseName
			}
		} else {
			Write-Host "No Trigger File found in [$PSScriptRoot]."
		}
	}

	#Registry
	If ($null -eq $Generated_ComputerName) {
		$registryPath = "HKLM:\SOFTWARE\CxName\ComputerRename"
		$valueName = "ComputerName"
		$Generated_ComputerName = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
		If ($null -eq $Generated_ComputerName) {
			Write-Host "No Computer Name found in Registry $registryPath\[$valueName]."
		} else {
			Write-Host "Computer Name found in Registry $registryPath\[$valueName] = $Generated_ComputerName"
		}
	}

	If (!(RC_Test-ComputerName -ComputerName $Generated_ComputerName)) {
		$tmpComputerName = $null
	} else {
		$tmpComputerName = $Generated_ComputerName
	}
	If ($null -eq $tmpComputerName) {
		Write-Host "No Computer Name Generated, please check logs for issues."
	} else {
		Write-Host "Generated Computer Name is [$tmpComputerName]."
	}
	$RC_ComputerObject.NewComputerName = $tmpComputerName
}

function RC_Test-ExistingComputerName {
	param(
		[String]$CurrentName,
		[string]$NewName
	)
	
	Write-Host "Current Computer Name is [$CurrentName] - New Computer Name is [$NewName]."
	If ($CurrentName -ine $NewName) {
		Return $false #Different Name
	} else {
		Return $true #Same Name
	}
}

function RC_Start-Reboot {
	RC_Remove_ScheduledTask
	if ($ComputerInformation.CsUserName -match "defaultUser") {
		Write-Host "Exiting during ESP/OOBE with return code 1641"
		RC_Exit-Script -ExitCode 1641
	} else {
		Write-Host "Initiating a restart in 10 minutes"
		& shutdown.exe /g /t 600 /f /c "Restarting the computer due to a computer name change.  Save your work."
		RC_Exit-Script -ExitCode 0
	}
}
function RC_New-ScheduledTask {
	RC_Remove_ScheduledTask
	# Copy myself to a safe place if not already there
	if (-not (Test-Path "$($RC_ComputerObject.ScratchSpace)\RenameComputer.ps1")) { 
		Write-Host "Copy PowerShell Script [$PSCommandPath] for Scheduled Task."
		Copy-Item $PSCommandPath "$($RC_ComputerObject.ScratchSpace)\RenameComputer.ps1" 
	}

	# Create the scheduled task action
	$action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy bypass -WindowStyle Hidden -File ""$($RC_ComputerObject.ScratchSpace)\RenameComputer.ps1"""

	# Create the scheduled task trigger
	$timespan = New-TimeSpan -Minutes 5
	$triggers = @()
	$triggers += New-ScheduledTaskTrigger -Daily -At 9am
	$triggers += New-ScheduledTaskTrigger -AtLogOn -RandomDelay $timespan
	$triggers += New-ScheduledTaskTrigger -AtStartup -RandomDelay $timespan
    
	# Register the scheduled task
	$Null = Register-ScheduledTask -User SYSTEM -Action $action -Trigger $triggers -TaskName "RenameComputer" -Description "RenameComputer" -Force
	Write-Host "New Scheduled task created."
}

function RC_Remove_ScheduledTask {
	$Task = Get-ScheduledTask -TaskName "Rename Computer" -ErrorAction SilentlyContinue
	If ($Null -ne $Task) {
		$Null = $Task | Disable-ScheduledTask
		$Null = $Task | Unregister-ScheduledTask -Confirm:$false
		Write-Host "Existing Scheduled task Removed."	
	}
}

function RC_Test-DomainMembership {
	# See if we are AD or AAD joined
	if ($ComputerInformation.CsPartOfDomain) {
		Write-Host "Device is joined to AD domain: $($ComputerInformation.CsDomain)"
		$RC_ComputerObject.isAD = $true
		RC_CheckAD
	} else {
		if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo") {
			$subKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
			$guids = $subKey.GetSubKeyNames()
			foreach ($guid in $guids) {
				$guidSubKey = $subKey.OpenSubKey($guid);
				$RC_ComputerObject.TenantId = $guidSubKey.GetValue("TenantId");
			}
		}
		if ($null -ne $($RC_ComputerObject.TenantId)) {
			Write-Host "Device is joined to AAD tenant: $($RC_ComputerObject.TenantId)"
			$RC_ComputerObject.isAAD = $true
		} else {
			Write-Host "Not part of a AAD or AD, in a workgroup."
		}
	}
}

function RC_CheckAD {
	if ($RC_ComputerObject.isAD) {
		$dcInfo = [ADSI]"LDAP://RootDSE"
		if ($null -eq $dcInfo.dnsHostName) {
			Write-Host "No connectivity to the domain, unable to rename at this point."
			$RC_ComputerObject.ADConnectivity = $false
		} else {
			Write-Host "Connectivity to the domain, okay to continue with rename process."
			$RC_ComputerObject.ADConnectivity = $true
		}
	}	
}

function RC_Initialize-ComputerObject {
	$RC_TempObject = @()

	$RC_TempObject = New-Object System.Object
	$RC_TempObject | Add-Member -type NoteProperty -Name isAD -Value $false
	$RC_TempObject | Add-Member -type NoteProperty -Name ADConnectivity -Value $false
	$RC_TempObject | Add-Member -type NoteProperty -Name isAAD -Value $false
	$RC_TempObject | Add-Member -type NoteProperty -Name ScratchSpace -Value $($env:TEMP)
	$RC_TempObject | Add-Member -type NoteProperty -Name GoodToGo -Value $false
	$RC_TempObject | Add-Member -type NoteProperty -Name TenantID -Value $null
	$RC_TempObject | Add-Member -type NoteProperty -Name ComputerName -Value $($env:COMPUTERNAME)
	$RC_TempObject | Add-Member -type NoteProperty -Name NewComputerName -Value $null
	#$RC_TempObject | Add-Member -type NoteProperty -name Enabled -value $Enabled
	$Script:RC_ComputerObject = $RC_TempObject

}

function RC_Exit-Script {
	param(
		[int]$ExitCode = 0
	)
	Stop-Transcript
	Exit $ExitCode
}

$RC_ComputerObject = @()

RC_Initialize-Script #Initialize Script with $RC_ComputerObject

RC_Test-Architecture #Test to ensure that we are running in x64

$ComputerInformation = Get-ComputerInfo #Get Computer Information

RC_Test-DomainMembership #Test AD / AAD Connectivity

RC_Generate-NewComputerName #Generate Computer Name based on parameters

If ($null -eq $RC_ComputerObject.NewComputerName) { 
	Write-Host "Computer Name not generated properly, will try again later."
	RC_Exit-Script -ExitCode 0
}

#Test if Same Name
If ((RC_Test-ExistingComputerName -CurrentName $($RC_ComputerObject.ComputerName) -NewName $($RC_ComputerObject.NewComputerName))) {
	Write-Host "Computer Name is already correct [$($RC_ComputerObject.NewComputerName)] - no need to rename computer."
	RC_Remove_ScheduledTask
	RC_Exit-Script -ExitCode 0
}

#AAD Joined
If ($($RC_ComputerObject.isAAD)) { 
	$RC_ComputerObject.GoodToGo = $true 
}

#AD Joined AND Domain Connectivity check
If ($RC_ComputerObject.isAD) {
	If ($RC_ComputerObject.ADConnectivity) { 
		$RC_ComputerObject.GoodToGo = $true 
	} else {
		$RC_ComputerObject.GoodToGo = $false 
	}
}

If (($RC_ComputerObject.GoodToGo)) {
	Write-Host "Computer is ready for rename."
	try {
		Rename-Computer -ComputerName $($RC_ComputerObject.ComputerName) -NewName $($RC_ComputerObject.NewComputerName) -Force -ErrorAction Stop
		RC_Start-Reboot
	} catch {
		Write-Host "Error attempting to rename Computer."
		RC_New-ScheduledTask
	}
} else {
	Write-Host "Computer is not ready for rename."
	RC_New-ScheduledTask
}

RC_Exit-Script -ExitCode 0