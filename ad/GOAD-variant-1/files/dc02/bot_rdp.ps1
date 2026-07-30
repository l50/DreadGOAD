# https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
if(-not(query session donna.nelson /server:apex)) {
  #kill process if exist
  Get-Process mstsc -IncludeUserName | Where {$_.UserName -eq "CLOUD\donna.nelson"}|Stop-Process
  #run the command
  mstsc /v:apex
}
