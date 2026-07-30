Get-ADUser -Identity "timothy" | Set-ADAccountControl -DoesNotRequirePreAuth:$true
