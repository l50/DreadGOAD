Get-ADUser -Identity "christine.reed" | Set-ADAccountControl -DoesNotRequirePreAuth:$true
