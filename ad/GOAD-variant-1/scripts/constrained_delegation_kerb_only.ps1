# https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition
$identity = 'apex$'
$spn = 'HTTP/delta.cloud.sigmatech.local'
$delegateTo = @('HTTP/delta.cloud.sigmatech.local', 'HTTP/delta')
# $delegateTo = @('CIFS/delta.cloud.sigmatech.local', 'CIFS/delta')

# Re-adding a value a multi-valued attribute already holds is an LDAP constraint
# violation, which fails the play on a lab reset, so only add what is missing.
$computer = Get-ADComputer -Identity $identity -Properties ServicePrincipalNames, 'msDS-AllowedToDelegateTo'

if ($computer.ServicePrincipalNames -notcontains $spn) {
    Set-ADComputer -Identity $identity -ServicePrincipalNames @{Add = $spn }
}

$missing = @($delegateTo | Where-Object { $computer.'msDS-AllowedToDelegateTo' -notcontains $_ })
if ($missing.Count -gt 0) {
    Set-ADComputer -Identity $identity -Add @{'msDS-AllowedToDelegateTo' = $missing }
}
