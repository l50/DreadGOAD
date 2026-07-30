# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition
Set-ADComputer -Identity "apex$" -ServicePrincipalNames @{Add='HTTP/delta.cloud.sigmatech.local'}
Set-ADComputer -Identity "apex$" -Add @{'msDS-AllowedToDelegateTo'=@('HTTP/delta.cloud.sigmatech.local','HTTP/delta')}
# Set-ADComputer -Identity "apex$" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/delta.cloud.sigmatech.local','CIFS/delta')}
