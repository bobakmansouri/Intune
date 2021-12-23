<#

how to run:

& '.\RetireDeviceApplicationAccess.ps1' -client_id theclientid -tenant_id thetenantid -client_secret theclientsecret -mail user@user.com -local_log_path C:\temp\DeviceDeprovReport.log -retire_TF TRUE
Babak Mansouri

This will remove devices associated with a user
logs will be written in 'C:\temp\DeviceDeprovReport.log',
devices will be removed without warning and confirmation
make syure you change application id poiting to the correct environment

#>

Param 
(         $client_id,
          $client_secret,
          $tenant_id,
          $mail,
          $local_log_path,
          $local_log_TF
)


####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User,
    $Password,
    $Client_id,
    $Client_secret,
    $Tenant_id
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."
Write-Log  "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        Write-Log "AzureAD PowerShell module not found, looking for AzureADPreview" 
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host

        Write-Log "AzureAD Powershell module not installed..." 
        Write-Log "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" 
        Write-Log "Script can't continue..." 
        
        
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }



[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null


$clientid = $Client_id
$tenantId = $Tenant_id
$clientSecret = $Client_secret



#$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"
# ADDED on 3-31
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"


$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

# ADDED on 3-31
$tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing

# ADDED on 3-31
# Access Token
$token = ($tokenRequest.Content | ConvertFrom-Json).access_token

return $token


}

function Write-Log {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,
        
        # EDIT with your location for the local log file
        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        #[string]$Path='C:\temp\DeviceDeprovReport.log',
        [string]$Path=$local_log_path,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
      #  $VerbosePreference = 'Continue'
        $VerbosePreference = 'Continue222'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

####################################################

Function Get-ManagedDevices(){

<#
.SYNOPSIS
This function is used to get Intune Managed Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Intune Managed Device
.EXAMPLE
Get-ManagedDevices
Returns all managed devices but excludes EAS devices registered within the Intune Service
.EXAMPLE
Get-ManagedDevices -IncludeEAS
Returns all managed devices including EAS devices registered within the Intune Service
.NOTES
NAME: Get-ManagedDevices
#>

[cmdletbinding()]

param
(
    [switch]$IncludeEAS,
    [switch]$ExcludeMDM
)

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "deviceManagement/managedDevices"

try {

    $Count_Params = 0

    if($IncludeEAS.IsPresent){ $Count_Params++ }
    if($ExcludeMDM.IsPresent){ $Count_Params++ }

        if($Count_Params -gt 1){

        write-warning "Multiple parameters set, specify a single parameter -IncludeEAS, -ExcludeMDM or no parameter against the function"
        Write-Host
        break

        }

        elseif($IncludeEAS){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

        }

        elseif($ExcludeMDM){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'eas'"

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?`$filter=managementAgent eq 'mdm' and managementAgent eq 'easmdm' and managementAgent eq 'googleCloudDevicePolicyController'"
        Write-Warning "EAS Devices are excluded by default, please use -IncludeEAS if you want to include those devices"
        Write-Host

        }




    
        ### uri is getting overridden here

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        #$DevicesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $DevicesResponse = (Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Get)

        $Devices = $DevicesResponse.value
         
        $DevicesNextLink = $DevicesResponse."@odata.nextLink"

        while ($DevicesNextLink -ne $null){

            #$DevicesResponse = (Invoke-RestMethod -Uri $DevicesNextLink -Headers $authToken -Method Get)
            $DevicesResponse = (Invoke-RestMethod -Uri $DevicesNextLink  -Headers @{Authorization = "Bearer $authToken"} -Method Get)
            $DevicesNextLink = $DevicesResponse."@odata.nextLink"
            $Devices += $DevicesResponse.value

        }

    return $Devices

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Log "Response content:`n$responseBody" 
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Get-AADUser(){

<#
.SYNOPSIS
This function is used to get AAD Users from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any users registered with AAD
.EXAMPLE
Get-AADUser
Returns all users registered with Azure AD
.EXAMPLE
Get-AADUser -userPrincipleName user@domain.com
Returns specific user by UserPrincipalName registered with Azure AD
.NOTES
NAME: Get-AADUser
#>

[cmdletbinding()]

param
(
    $userPrincipalName,
    $Property
)

# Defining Variables
$graphApiVersion = "v1.0"
$User_resource = "users"

    try {

        if($userPrincipalName -eq "" -or $userPrincipalName -eq $null){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)"
       # (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
         (Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Get).Value

        }

        else {

            if($Property -eq "" -or $Property -eq $null){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName"
            Write-Verbose $uri
            #Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Get
            }

            else {

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($User_resource)/$userPrincipalName/$Property"
            Write-Verbose $uri
           # (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            (Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Get).Value
            }

        }

    }

    catch {

 #   $ex = $_.Exception
 #   $errorResponse = $ex.Response.GetResponseStream()
 #   $reader = New-Object System.IO.StreamReader($errorResponse)
 #   $reader.BaseStream.Position = 0
 #   $reader.DiscardBufferedData()
 #   $responseBody = $reader.ReadToEnd();
 #   Write-Host "Response content:`n$responseBody" -f Red
 #   Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
   Write-Host "User $userPrincipalName doesnt exist" -ForegroundColor DarkCyan
   Write-Log "User $userPrincipalName doesnt exist..." 
   
    write-host
    break

    }

}

####################################################

Function Get-AADUserDevices(){

<#
.SYNOPSIS
This function is used to get the AAD User Devices from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a users devices registered with Intune MDM
.EXAMPLE
Get-AADUserDevices -UserID $UserID
Returns all user devices registered in Intune MDM
.NOTES
NAME: Get-AADUserDevices
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="UserID (guid) for the user you want to take action on must be specified:")]
    $UserID
)

# Defining Variables
$graphApiVersion = "v1.0"
$Resource = "users/$UserID/managedDevices"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Write-Verbose $uri
    (Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Get).Value
    }

    catch {


    write-host "User $UserID doesn't have any owned Devices..." -f Yellow
    write-log "User $UserID doesn't have any owned Devices..."
    write-host
    break

    }

}


####################################################
####################################################

Function Invoke-DeviceAction(){

<#
.SYNOPSIS
This function is used to set a generic intune resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and sets a generic Intune Resource
.EXAMPLE
Invoke-DeviceAction -DeviceID $DeviceID -remoteLock
Resets a managed device passcode
.NOTES
NAME: Invoke-DeviceAction
#>

[cmdletbinding()]

param
(
    [switch]$RemoteLock,
    [switch]$ResetPasscode,
    [switch]$Wipe,
    [switch]$Retire,
    [switch]$Delete,
    [switch]$Sync,
    [switch]$Rename,
    [Parameter(Mandatory=$true,HelpMessage="DeviceId (guid) for the Device you want to take action on must be specified:")]
    $DeviceID
)

$graphApiVersion = "Beta"

    try {

        $Count_Params = 0

        if($RemoteLock.IsPresent){ $Count_Params++ }
        if($ResetPasscode.IsPresent){ $Count_Params++ }
        if($Wipe.IsPresent){ $Count_Params++ }
        if($Retire.IsPresent){ $Count_Params++ }
        if($Delete.IsPresent){ $Count_Params++ }
        if($Sync.IsPresent){ $Count_Params++ }
        if($Rename.IsPresent){ $Count_Params++ }

        if($Count_Params -eq 0){

        write-host "No parameter set, specify -RemoteLock -ResetPasscode -Wipe -Delete -Sync or -rename against the function" -f Red

        }

        elseif($Count_Params -gt 1){

        write-host "Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode -Wipe -Delete or -Sync against the function" -f Red

        }

        elseif($RemoteLock){

        # DO NOTHING

        }

        elseif($ResetPasscode){

           # DO NOTHING

        }

        elseif($Wipe){

       # DO NOTHING

        }

        elseif($Retire){

        write-host
     

            $Resource = "deviceManagement/managedDevices/$DeviceID/retire"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending retire command to $DeviceID"
            Write-Log  "Sending retire command to $DeviceID"
            #Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
           Invoke-RestMethod -Uri $uri  -Headers @{Authorization = "Bearer $authToken"} -Method Post

      

        }

        elseif($Delete){

       # DO NOTHING

        }
        
        elseif($Sync){

        # DO NOTHING

        }

        elseif($Rename){

        # DO NOTHING

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

# EDIT info with service account and credential.txt file location
$User = "ezbob74@dummy.com"

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        Write-Log "Authentication Token expired $($TokenExpires) minutes ago"
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User -Password "$Password" -Client_id $client_id -Client_secret $client_secret -Tenant_id $tenant_id
        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken   -User $User -Password "$Password" -Client_id $client_id -Client_secret $client_secret -Tenant_id $tenant_id

}

#endregion

####################################################

$ExportPath=$local_log_path

    # If the directory path doesn't exist prompt user to create the directory

    if(!(Test-Path "$ExportPath")){

    Write-Host
    Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
    Write-Log "Path $($ExportPath) doesn't exist, do you want to create this directory? Y or N?"
    $Confirm = read-host

        if($Confirm -eq "y" -or $Confirm -eq "Y"){

        new-item -ItemType Directory -Path "$ExportPath" | Out-Null
        Write-Host

        }

        else {

        Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
        Write-Log "Creation of directory path was cancelled..." 
        Write-Host
        break

        }

    }

Write-Host





####################################################

####################################################

write-host


# Get the email from the param list
$UPN = $mail


write-host

try{

$User = Get-AADUser -userPrincipalName $UPN

$id = $User.id
write-host "User ID:"$id
Write-Log   "User ID:"$id
####################################################
# Get Users Devices
####################################################
$dName = $User.displayName
Write-Host
Write-Host "Checking if the user" $User.displayName "has any devices assigned..." -ForegroundColor DarkCyan
Write-Log "Checking if the user $dName has any devices assigned..." 

}
catch{

#Write-Host "User doesnt exist" -ForegroundColor DarkCyan
#Write-Log "User doesnt exist..." 

}

try{

$Devices = Get-AADUserDevices -UserID $id

####################################################
# Invoke-DeviceAction - RETIRE
####################################################

if($Devices){

$DeviceCount = @($Devices).count

Write-Host
Write-Host "User has $DeviceCount devices added to Intune..."
Write-Host
Write-Log  "User has $DeviceCount devices added to Intune..."

    if($Devices.id.count -gt 1){

    $Managed_Devices = $Devices.deviceName | sort -Unique

    $Managed_Devicesid = $Devices.id | sort -Unique
   
   for ($i=1;$i -le $Managed_Devicesid.count; $i++) {
     Write-Host "$i. $($Managed_Devicesid[$i-1])" 

        $dUser = $User.userPrincipalName

        $message =  "User " + $User.userPrincipalName + " has device " + $($Managed_Devicesid[$i-1]) +  " and is being retired."
        Write-Host $message
        Write-Log  $message
   
        Invoke-DeviceAction -DeviceID $($Managed_Devicesid[$i-1]) -Retire -Verbose
   

        }

    }

    elseif($Devices.id.count -eq 1){

     $Managed_Devicesid = $Devices.id | sort -Unique

     for ($i=1;$i -le $Managed_Devicesid.count; $i++) {
     Write-Host "$i. $($Managed_Devicesid[$i-1])" 
    }
        
        $message = "User " + $User.userPrincipalName + " has one device " + $Devices.deviceName + " that is being retired."

        write-host $message
        Write-Log $message
    
       Invoke-DeviceAction -DeviceID $Devices.id -Retire -Verbose

    }

}

else {

Write-Host
#write-host "User $UPN doesn't have any owned Devices..." -f Yellow
#write-log "User $UPN doesn't have any owned Devices..."

}

write-host

}
catch{

Write-Host
#write-host "User $UPN doesn't have any owned Devices..." -f Yellow
#write-log "User $UPN doesn't have any owned Devices..."

}
