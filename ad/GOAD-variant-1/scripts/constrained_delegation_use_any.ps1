$identity = 'anthony.green'
$spn = 'CIFS/thewall.cloud.sigmatech.local'
$delegateTo = @('CIFS/delta.cloud.sigmatech.local', 'CIFS/delta')

# Re-adding a value a multi-valued attribute already holds is an LDAP constraint
# violation, which fails the play on a lab reset, so only add what is missing.
# anthony.green already carries a kerberoastable SPN from ad-data: add, never replace.
$user = Get-ADUser -Identity $identity -Properties ServicePrincipalNames, 'msDS-AllowedToDelegateTo'

if ($user.ServicePrincipalNames -notcontains $spn) {
    Set-ADUser -Identity $identity -ServicePrincipalNames @{Add = $spn }
}

Set-ADAccountControl -Identity $identity -TrustedToAuthForDelegation $true

$missing = @($delegateTo | Where-Object { $user.'msDS-AllowedToDelegateTo' -notcontains $_ })
if ($missing.Count -gt 0) {
    Set-ADUser -Identity $identity -Add @{'msDS-AllowedToDelegateTo' = $missing }
}
