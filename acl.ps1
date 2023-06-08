# Get the file path
$filePath = "C:\Users\Lasha_Pertakhia\Documents\learnspace\podcast-generator\entrypoint.sh"
# $filePath = Get-Item "C:\Users\Lasha_Pertakhia\Documents\learnspace\podcast-generator\entrypoint.sh"

$user = "Everyone"

$accesstype = "FullControl"
# $permissions = "Read", "Write", "Execute"

$allowOrDeny = "Allow"

$argList = $user,$accesstype,$allowOrDeny

$acl = Get-Acl $filePath
# $acl = Get-Acl -Path $filePath

$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $argList
# $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $permissions, $allowOrDeny)
# $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $permissions, "ContainerInherit, ObjectInherit", "None", $allowOrDeny)
# $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, $permissions, "ContainerInherit, ObjectInherit", "None", $allowOrDeny)

$acl.SetAccessRule($AccessRule)
# $acl.AddAccessRule($AccessRule)

$acl | Set-Acl $filePath
# Set-Acl -Path $filePath -AclObject $acl
# Set-Acl -Path $filePath -AclObject $acl -Recurse
# Set-Acl -Path $filePath -AclObject $acl

#https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl?view=powershell-7.1

#https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=net-5.0
