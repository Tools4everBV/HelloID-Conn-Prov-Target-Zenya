#####################################################
# HelloID-Conn-Prov-Target-Zenya-ResourceCreation-Groups-Departments
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json

# The resourceData used in this default script uses resources based on Title
$rRef = $resourceContext | ConvertFrom-Json
$success = $true

$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Used to connect to Zenya Scim endpoints
$baseUrl = $c.serviceAddress
$clientId = $c.clientId
$clientSecret = $c.clientSecret

# Troubleshooting
# $dryRun = $false

# Name format: Department-<department code>
$groupNamePrefix = "Department-"
$groupNameSuffix = ""

#region Functions
function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose 'Creating Access Token'

        $authorizationurl = "$baseUrl/oauth/token"
        $authorizationbody = @{
            "grant_type"                = 'client_credentials'
            "client_id"                 = $ClientId
            "client_secret"             = $ClientSecret
            "token_expiration_disabled" = $false
        } | ConvertTo-Json -Depth 10
        $AccessToken = Invoke-RestMethod -uri $authorizationurl -body $authorizationbody -Method Post -ContentType "application/json"

        Write-Verbose 'Adding Authorization headers'
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "$($AccessToken.token_type) $($AccessToken.access_token)")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        Write-Output $headers
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion Functions

# In preview only the first 10 items of the SourceData are used
foreach ($resource in $rRef.SourceData) {
    # Write-Information "Checking $($resource)"
    try {
        $groupName = ("$groupNamePrefix" + "$($resource.ExternalId)" + "$groupNameSuffix")

        $group = [PSCustomObject]@{
            schemas      = "urn:ietf:params:scim:schemas:core:2.0:Group"
            display_name = $groupName
        }

        $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

        Write-Verbose "Group lookup based on display name [$($group.display_name)]"
        $splatWebRequest = @{
            Uri     = "$baseUrl/scim/groups?filter=displayName%20eq%20%22$($group.display_name)%22"
            Headers = $headers
            Method  = 'GET'
        }

        $currentGroup = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

        if ($currentGroup.Id.count -ge 1) {
            $groupExists = $true
        }
        else {
            $groupExists = $false
        }

        # If resource does not exist
        if ($groupExists -eq $False) {
            <# Resource creation preview uses a timeout of 30 seconds
            while actual run has timeout of 10 minutes #>
            Write-Information "Creating $($group.display_name)"

            if (-Not($dryRun -eq $True)) {
                $body = ($group | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri     = "$baseUrl/scim/groups"
                    Headers = $headers
                    Method  = 'POST'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
                }

                $createdGroup = Invoke-RestMethod @splatWebRequest -Verbose:$false

                $success = $True
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Successfully created group $($createdGroup.displayName) ($($createdGroup.Id))"
                        Action  = "CreateResource"
                        IsError = $false
                    })
            }
        }
        else {
            if ($debug -eq $true) { Write-Warning "Group $($group.display_name) already exists" }
            $success = $True
            $auditLogs.Add([PSCustomObject]@{
                    Message = "Skipped group $($group.display_name)"
                    Action  = "CreateResource"
                    IsError = $false
                })
        }
        
    }
    catch {
        $success = $false
        $ex = $PSItem
        if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
            $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorMessageDetail = $null
            $errorObjectConverted = $ex | ConvertFrom-Json -ErrorAction SilentlyContinue
    
            if($null -ne $errorObjectConverted.detail){
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '\{(.*?)\}').Value
                if($null -ne $errorObjectDetail){
                    $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if($null -ne $errorDetailConverted){
                        $errorMessageDetail = $errorDetailConverted.title
                    }else{
                        $errorMessageDetail = $errorObjectDetail
                    }
                }else{
                    $errorMessageDetail = $errorObjectConverted.detail
                }
            }else{
                $errorMessageDetail = $ex
            }

            $errorMessage = "Could not create Zenya group $($group.display_name). Error: $($errorMessageDetail)"
        }
        else {
            $errorMessage = "Could not create Zenya group $($group.display_name). Error: $($ex.Exception.Message)"
        }
    
        $verboseErrorMessage = "Could not create Zenya group $($group.display_name). Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error message: $($ex)"
        Write-Verbose $verboseErrorMessage
      
        $auditLogs.Add([PSCustomObject]@{
                Message = $errorMessage
                Action  = "CreateResource"
                IsError = $true
            })
    }
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10