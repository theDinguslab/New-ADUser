<#
Dave Ramsay
Student# 1358998
This powershell script rovides advanced functions to create Active Directory users, with 
departmental group assignments, and safely remove them.
#>


<#function NewITYADUser#>
function New-ITYADUser {
    #Support named parameters only by disabling positional binding
    [CmdletBinding(PositionalBinding = $false)]
    param(
        #Mandatory first name parameter validated as non-empty
        [Parameter(Mandatory = $true, HelpMessage = "Please enter the user's first name.")]
        [ValidateNotNullOrEmpty()]
        [string]$FirstName,

        #Mandatory last Name parameter validated as not null or empty
        [Parameter(Mandatory = $true, HelpMessage = "Please enter the user's last name.")]
        [ValidateNotNullOrEmpty()]
        [string]$LastName,

        #Mandatory username parameter validated for a minimum length of 3 characters (no max)
        [Parameter(Mandatory = $true, HelpMessage = "Please enter the username (minimum 3 characters).")]
        [ValidateLength(3, [int]::MaxValue)]
        [string]$Username,

        #Mandatory password parameter validated between 8 and 15 characters inclusive
        [Parameter(Mandatory = $true, HelpMessage = "Please enter a plain text password (8 to 15 characters).")]
        [ValidateLength(8, 15)]
        [string]$Password,

        #Mandatory department parameter validated to be exactly 5 characters
        [Parameter(Mandatory = $true, HelpMessage = "Please enter the 5-character department code (e.g., SALES, FINCE).")]
        [ValidateLength(5, 5)]
        [string]$Department
    )

    #check if the username already exists. if so, output error message and return -1
    $ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$Username'"
    if ($null -ne $ExistingUser) {
        Write-Host "Error! User '$Username' already exists in Active Directory."
        return -1
    }

    #Convert plain text password to secure string
    $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    #Create new AD user account using all provided parameters and secure password
    $FullName = "$FirstName $LastName"
    New-ADUser -Name $FullName `
               -GivenName $FirstName `
               -Surname $LastName `
               -SamAccountName $Username `
               -UserPrincipalName "$Username@$((Get-ADDomain).DNSRoot)" `
               -Department $Department `
               -AccountPassword $SecurePassword `
               -Enabled $true

    # Verify whether new user was added to AD and return -2 if not found
    $CreatedUser = Get-ADUser -Filter "SamAccountName -eq '$Username'"
    if ($null -eq $CreatedUser) {
        return -2
    }

    #Check if the user's department group exists and create it if it doesn't 
    $DeptGroup = Get-ADGroup -Filter "Name -eq '$Department'"
    if ($null -eq $DeptGroup) {
        New-ADGroup -Name $Department -GroupScope Global -GroupCategory Security
    }
    #Add new user to departmental group
    Add-ADGroupMember -Identity $Department -Members $Username

    #Verify user is a member of the departmental group. return 0 on success, otherwise -3
    $GroupMembers = Get-ADGroupMember -Identity $Department
    if ($GroupMembers.SamAccountName -contains $Username) {
        return 0
    }
    else {
        return -3
    }
}



<#function Remove-ITYADUser#>
function Remove-ITYADUser {
    #Accept both named and positional parameters
    [CmdletBinding()]
    param(
        # Mandatory parameter for Username, SID, or DN, validated for at least 3 characters
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Enter the user's Username, SID, or Distinguished Name.")]
        [ValidateLength(3, [int]::MaxValue)]
        [string]$Identity
    )

    #Check if user account exists (handling Username, SID, or DN) and get Department property
    $UserObj = $null
    if ($Identity -like "CN=*" -or $Identity -like "S-1-5-*") {
        $UserObj = Get-ADUser -Filter "DistinguishedName -eq '$Identity' -or SID -eq '$Identity'" -Properties Department
    }
    else {
        $UserObj = Get-ADUser -Filter "SamAccountName -eq '$Identity'" -Properties Department
    }

    if ($null -eq $UserObj) {
        return -1
    }

    #Get accounts department information and save it in a variable
    $UserDepartment = $UserObj.Department

    #Remove users account from the departmental group only (if a department is assigned and the group exists)
    if (-not [string]::IsNullOrEmpty($UserDepartment)) {
        $DeptGroup = Get-ADGroup -Filter "Name -eq '$UserDepartment'"
        if ($null -ne $DeptGroup) {
            Remove-ADGroupMember -Identity $DeptGroup -Members $UserObj -Confirm:$false
        }
    }

    #Remove user account from Active Directory
    Remove-ADUser -Identity $UserObj -Confirm:$false
}



<#Test#>
# New-ITYADUser with 3 users (2 = same department, 1 = different department) 
# will immediately check return codes after each call and exit with message if an error occurs

$Result1 = New-ITYADUser -FirstName "Geordie" -LastName "LaForge" -Username "glaforge" -Password "Password123!" -Department "SALES"
if ($Result1 -ne 0) {
    Write-Host "Failed to create user glaforge. Return code: $Result1"
    exit
}

$Result2 = New-ITYADUser -FirstName "Benjamin" -LastName "Sisko" -Username "bsisko" -Password "Password123!" -Department "SALES"
if ($Result2 -ne 0) {
    Write-Host "Failed to create user bsisko. Return code: $Result2"
    exit
}

$Result3 = New-ITYADUser -FirstName "Miles" -LastName "O'Brien" -Username "mobrien" -Password "Password123!" -Department "FINCE"
if ($Result3 -ne 0) {
    Write-Host "Failed to create user mobrien. Return code: $Result3"
    exit
}

#test Remove-ITYADUser by removing the 3 users created above
Remove-ITYADUser -Identity "glaforge"
Remove-ITYADUser -Identity "bsisko"
Remove-ITYADUser -Identity "mobrien"