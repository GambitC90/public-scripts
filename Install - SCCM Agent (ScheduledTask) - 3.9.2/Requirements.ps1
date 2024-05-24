$Service = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
If ($null -ne $Service){
    Write-Host "CCMExec Discovered"
} else {
    Write-Host "Install CCMExec"
}