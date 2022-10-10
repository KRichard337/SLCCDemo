#Other Useful Cmdlets
Test-NetConnection
Add-Computer
Get-Member
Get-Help
Out-GridView
Export-Csv
Get-ChildItem
Get-History
Set-Clipboard
Get-NetConnectionProfile
Set-NetConnectionProfile
'whatif parameter'
'Ctrl + Space hotkey!'

#Give SVR IP Addr.
New-NetIPAddress -InterfaceAlias Ethernet1 -AddressFamily IPv4 -IPAddress 10.0.1.10 -PrefixLength 24 -DefaultGateway 10.0.1.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet1 -ServerAddresses 10.0.1.1

#Change Name, Timezone and Restart
Rename-Computer -NewName DC2016
Set-TimeZone -Id "Central Standard Time"

Restart-Computer

#Install ADDS
Install-WindowsFeature -Name AD-Domain-Services 

$SafeModeAdmin = ConvertTo-SecureString -String "Sup3rS3cr3tP4$$" -AsPlainText -Force

Install-ADDSForest -DomainName test.domain -InstallDns -SafeModeAdministratorPassword $SafeModeAdmin -Confirm:$false 

Add-WindowsFeature RSAT-ADDS-Tools

#Add AD Users

$users = Import-CSV .\names.csv

foreach ($user in $users){
try{
New-ADUser -GivenName $user.Givenname -Surname $user.Surname -Name ($user.givenname + " " + $user.surname) -Department $user.Department -Title $user.Title -Description $user.title -UserPrincipalName ($user.givenname + $user.surname+"@test.domain") -SamAccountName ($user.givenname + $user.surname) -AccountPassword (ConvertTo-SecureString -String "Password12345" -AsPlainText -Force) -ChangePasswordAtLogon $true -Enabled $true
}
catch {
$user | Out-File -FilePath .\failed.txt -Append
}
}

#delete all the users
foreach ($user in $users){
Remove-ADUser -Identity ($user.givenname + $user.surname) -Confirm:$false
}


#Add UPN Suffix

Get-ADForest | Set-ADForest -UPNSuffixes @{add="testdomain.com"}

#Change users UPN Suffix
foreach ($user in $users){
Set-ADUser -Identity ($user.givenname + $user.surname) -UserPrincipalName ($user.givenname + $user.surname + "@testdomain.com")}

#Find all users with blank descriptions

$nodescription = Get-aduser -Properties description,title -filter {description -notlike "*"}

#create AD Group
New-ADGroup -Name "Test Group" -GroupScope Global

#create OU
New-ADOrganizationalUnit -Name "Information Technology" -Path "DC=test,DC=Domain"
New-ADOrganizationalUnit -Name "Terminated Users" -Path "DC=test,DC=Domain"
New-ADOrganizationalUnit -Name "Department Groups" -Path "DC=test,DC=Domain"
New-ADOrganizationalUnit -Name "Test1" -Path "DC=test,DC=Domain"
New-ADOrganizationalUnit -Name "Test2" -Path "DC=test,DC=Domain"


#create all the ad groups
$users.department | Sort-Object -Unique | ForEach-Object {New-ADGroup -Name $_ -GroupScope Global -Path "OU=Department Groups, dc=test,dc=domain"}


$ITUsers = get-aduser -filter {department -eq "IT"}

#Add users to group
$ITUsers | ForEach-Object {Add-ADGroupMember -identity "IT" -Members $_ }
#or
Add-ADGroupMember -Identity 'IT' -Members $ITUsers

#Move Users to OU
$ITUsers | ForEach-Object { Move-ADObject -Identity $_ -TargetPath "ou=Information Technology,dc=test,dc=domain"}


#terminate user
$username = "jameslittle"

$termdate = Get-Date -Format yyyyMMdd
Set-ADUser -Identity $username -Enabled:$false -Description "Disabled on $termdate" -PassThru | Move-ADObject -TargetPath "ou= terminated users,dc=test,dc=domain"

#remove empty OUs

Get-ADOrganizationalUnit -filter * | ForEach-Object {if (-not (Get-ADObject -SearchBase $_ -SearchScope OneLevel -Filter *)) {Set-ADOrganizationalUnit $_ -ProtectedFromAccidentalDeletion:$false 
 Remove-ADOrganizationalUnit $_ -Confirm:$false }
}

#Reset Password (This is typically built into a function)
$username = 'jameslittle'
Set-ADAccountPassword -identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword12345" -Force)
Set-ADUser -Identity $username -ChangePasswordAtLogon $true 


#Here's what that function would look like:
function Reset-ADUserPassword {
param(

[string]$Username,
[string]$password = "NewPassword12345"
)
Set-ADAccountPassword -identity $username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewPassword12345" -Force)
Set-ADUser -Identity $username -ChangePasswordAtLogon $true 

}
Reset-ADUserPassword -Username travisisrael -password "idontneedtoputone12345"

#DNS Stuff

Get-Command Add-DnsServerResrouceRecord*

Add-DnsServerResourceRecordCName -HostNameAlias dc2016.test.domain -name test -ZoneName test.domain
Add-DnsServerResourceRecordA -Name filesvr -IPv4Address 192.168.1.100 -ZoneName test.domain

Remove-DnsServerResourceRecord  -Name filesvr -ZoneName test.domain -RRType a -force -WhatIf
Remove-DnsServerResourceRecord  -Name filesvr -ZoneName test.domain -RRType a -force 