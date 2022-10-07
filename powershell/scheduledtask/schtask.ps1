# Distilled Security - Phil Davies
#04-10-2022

#Check Scheduled task
Write-Host "#########>Take Scheduled task Information<#########" -ForegroundColor DarkGreen
$schtasksCSV = "./Scheduled-task- " + ".csv"
$tabletasks = Get-ScheduledTask |Select-Object -Property *
$resultTask= @()

#Iterate findings
foreach ($tasks in $tabletasks) {
$taskactions = Get-ScheduledTask $tasks.Taskname |Select-Object -ExpandProperty Actions

 foreach ( $taskaction in $taskactions ) {


$resultTasktemp = [PSCustomObject]@{
                            Task_name = $tasks.Taskname
                            Task_URI = $tasks.URI
                            Task_state = $tasks.State
                            Task_Author = $tasks.Author
			    Task_Description = $tasks.Description
                            Task_action = $taskaction.Execute
                            Task_action_Argument = $taskaction.Arguments
                            Task_Action_WorkingDirectory = $taskaction.WorkingDirectory
							
                        }
 #                       write-host $taskaction.Execute

#Hunting String in Executable Property
If($taskaction.Execute -like  "*certutil.exe*")
{
     Write-host "Found malware on" $env:COMPUTERNAME "in" $tasks.TaskName
     Resolve-DNSName -Name $env:COMPUTERNAME-"Malware-Found.isitfound.distilled.info"
}

$resultTask += $resultTasktemp

 }
  }
  

#Grab all scheduled tasks in case we need it later
$resultTask | Export-Csv -NoTypeInformation $schtasksCSV

