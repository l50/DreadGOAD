$task = '/c powershell New-PSDrive -Name "Public" -PSProvider "FileSystem" -Root "\\Citadel\Private"'
$repeat = (New-TimeSpan -Minutes 5)
$taskName = "ntlm_bot"
$user = "cloud.sigmatech.local\michael.nguyen"
$password = "{{ lab.domains[lab.hosts.dc02.domain].users['michael.nguyen'].password }}"

$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "$task"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval $repeat
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $user -Password $password -Settings $settings -Force
