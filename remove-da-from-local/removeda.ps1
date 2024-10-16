# Script to remove Domain Admins from the local Administrators group
$GroupName = "Administrators"
$DomainAdminGroup = "Domain Admins"

# Retrieve the local Administrators group
$localAdminGroup = [ADSI]"WinNT://./$GroupName,group"

# Iterate over the members of the local Administrators group
$localAdminGroup.Members() | ForEach-Object {
    $user = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)

    # If the user is "Domain Admins", remove it from the local Administrators group
    if ($user -eq $DomainAdminGroup) {
        try {
            $localAdminGroup.Remove("WinNT://$user")
            Write-Host "Successfully removed $user from the local Administrators group"
        } catch {
            Write-Host "Error removing $user from the local Administrators group: $_"
        }
    }
}
