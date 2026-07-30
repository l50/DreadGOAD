Set-ADUser -Identity "anthony.green" -ServicePrincipalNames @{Add='CIFS/thewall.cloud.sigmatech.local'}
Get-ADUser -Identity "anthony.green" | Set-ADAccountControl -TrustedToAuthForDelegation $true
Set-ADUser -Identity "anthony.green" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/delta.cloud.sigmatech.local','CIFS/delta')}
