Get-ADUser -Identity "samantha.lewis" | Set-ADAccountControl -TrustedForDelegation $true
