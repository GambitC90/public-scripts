<#

.SYNOPSIS
PSAppDeployToolkit.Extensions - Provides the ability to extend and customize the toolkit by adding your own functions that can be re-used.

.DESCRIPTION
This module is a template that allows you to extend the toolkit with your own custom functions.

This module is imported by the Invoke-AppDeployToolkit.ps1 script which is used when installing or uninstalling an application.

PSAppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2024 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham, Muhammad Mashwani, Mitch Richters, Dan Gough).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.LINK
https://psappdeploytoolkit.com

#>

##*===============================================
##* MARK: MODULE GLOBAL SETUP
##*===============================================

# Set strict error handling across entire module.
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-StrictMode -Version 1


##*===============================================
##* MARK: FUNCTION LISTINGS
##*===============================================

function New-ADTExampleFunction {
    <#
    .SYNOPSIS
        Basis for a new PSAppDeployToolkit extension function.

    .DESCRIPTION
        This function serves as the basis for a new PSAppDeployToolkit extension function.

    .INPUTS
        None

        You cannot pipe objects to this function.

    .OUTPUTS
        None

        This function does not return any output.

    .EXAMPLE
        New-ADTExampleFunction

        Invokes the New-ADTExampleFunction function and returns any output.
    #>

    [CmdletBinding()]
    param
    (
    )

    begin {
        # Initialize function.
        Initialize-ADTFunction -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
    }

    process {
        try {
            try {
            } catch {
                # Re-writing the ErrorRecord with Write-Error ensures the correct PositionMessage is used.
                Write-Error -ErrorRecord $_
            }
        } catch {
            # Process the caught error, log it and throw depending on the specified ErrorAction.
            Invoke-ADTFunctionErrorHandler -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState -ErrorRecord $_
        }
    }

    end {
        # Finalize function.
        Complete-ADTFunction -Cmdlet $PSCmdlet
    }
}

function Remove-RC_ScheduledTask {
    param (
        [string]$TaskName
    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    If ($Null -ne $Task) {
        Write-ADTLogEntry -Message "Existing Scheduled Task [$TaskName] found - Deleting task." -Severity 1 -Source ${CmdletName}
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        If ($Null -eq $Task) {
            Write-ADTLogEntry -Message "Scheduled Task [$TaskName] deleted." -Severity 1 -Source ${CmdletName}
        } else {
            Write-ADTLogEntry -Message "Scheduled Task [$TaskName] failed to delete." -Severity 3 -Source ${CmdletName}
            $adtSession.SetExitCode(1)
        }
    }
}

function New-RenameComputerScheduledTask {
    param(
        [string]$TaskName
    )

    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    Remove-RC_ScheduledTask -TaskName $TaskName

    $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c Powershell.exe -NoProfile -WindowStyle Hidden -File ""$($ENV:ProgramFiles)\Rename Computer\RenameComputer.ps1"""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Null = Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName $TaskName -Description "Rename Computer after HybridAD Join from AutoPilot"

    $Task = Get-ScheduledTask -TaskName $TaskName
    If ($null -ne $Task) {
        Write-ADTLogEntry -Message "Scheduled Task [$TaskName] created." -Severity 1 -Source ${CmdletName}
    } Else {
        Write-ADTLogEntry -Message "Scheduled Task [$TaskName] NOT created." -Severity 3 -Source ${CmdletName}
        $adtSession.SetExitCode(1)
    }
}


##*===============================================
##* MARK: SCRIPT BODY
##*===============================================

# Announce successful importation of module.
Write-ADTLogEntry -Message "Module [$($MyInvocation.MyCommand.ScriptBlock.Module.Name)] imported successfully." -ScriptSection Initialization
