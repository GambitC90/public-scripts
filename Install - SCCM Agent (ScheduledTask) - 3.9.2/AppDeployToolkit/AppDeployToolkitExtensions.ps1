<#
.SYNOPSIS

PSAppDeployToolkit - Provides the ability to extend and customise the toolkit by adding your own functions that can be re-used.

.DESCRIPTION

This script is a template that allows you to extend the toolkit with your own custom functions.

This script is dot-sourced by the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.

PSApppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2023 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham and Muhammad Mashwani).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.EXAMPLE

powershell.exe -File .\AppDeployToolkitHelp.ps1

.INPUTS

None

You cannot pipe objects to this script.

.OUTPUTS

None

This script does not generate any output.

.NOTES

.LINK

https://psappdeploytoolkit.com
#>


[CmdletBinding()]
Param (
)

##*===============================================
##* VARIABLE DECLARATION
##*===============================================

# Variables: Script
[string]$appDeployToolkitExtName = 'PSAppDeployToolkitExt'
[string]$appDeployExtScriptFriendlyName = 'App Deploy Toolkit Extensions'
[version]$appDeployExtScriptVersion = [version]'3.9.2'
[string]$appDeployExtScriptDate = '02/02/2023'
[hashtable]$appDeployExtScriptParameters = $PSBoundParameters

##*===============================================
##* FUNCTION LISTINGS
##*===============================================

# <Your custom functions go here>

function Remove-ScheduledTask {
    param (
        [string]$TaskName,
        [string]$TaskPath = "\"
    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    $Task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    If ($Null -ne $Task) {
        Write-Log -Message "Existing Scheduled Task [$TaskName] found - Deleting task." -Severity 1 -Source ${CmdletName}
        $Task | Unregister-ScheduledTask -Confirm:$false
        $Task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        If ($Null -eq $Task) {
            Write-Log -Message "Scheduled Task [$TaskName] deleted." -Severity 1 -Source ${CmdletName}
            $mainExitCode = 1
        }
        else {
            Write-Log -Message "Scheduled Task [$TaskName] failed to delete." -Severity 3 -Source ${CmdletName}
            $mainExitCode = 1
        }
    }
}

function New-ScheduledTask {
    param(
        [string]$TaskName,
        [string]$TaskPath = "\", #\ = Root
        [string]$TaskExecute,
        [string]$TaskExecuteArguments

    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    Remove-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
  
    $Action = New-ScheduledTaskAction -Execute $TaskExecute -Argument $TaskExecuteArguments

    $Trigger = New-ScheduledTaskTrigger -AtLogOn

    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -TaskName $TaskName -TaskPath $TaskPath | Out-Null

    $Task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    If ($null -ne $Task) {
        Write-Log -Message "Scheduled Task [$TaskName] created." -Severity 1 -Source ${CmdletName}
        Write-Log -Message "Scheduled Task to Run: [$($("$($Task.Actions.Execute) $($Task.Actions.Arguments)").Trim())]" -Severity 1 -Source ${CmdletName}
    }
    Else {
        Write-Log -Message "Scheduled Task [$TaskName] NOT created." -Severity 3 -Source ${CmdletName}
    }
}


##*===============================================
##* END FUNCTION LISTINGS
##*===============================================

##*===============================================
##* SCRIPT BODY
##*===============================================

If ($scriptParentPath) {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] dot-source invoked by [$(((Get-Variable -Name MyInvocation).Value).ScriptName)]" -Source $appDeployToolkitExtName
}
Else {
    Write-Log -Message "Script [$($MyInvocation.MyCommand.Definition)] invoked directly" -Source $appDeployToolkitExtName
}

##*===============================================
##* END SCRIPT BODY
##*===============================================
