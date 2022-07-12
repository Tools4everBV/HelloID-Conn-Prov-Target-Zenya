#####################################################
# HelloID-Conn-Prov-Target-Zenya-GrantPermission-Group
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json

# The permissionReference object contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json
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
# $aRef = @{
#     userName = "TestHelloID@enyoi.onmicrosoft.com"
#     id       = "64e1c737-0274-4ba6-ae12-201edbe77d99"
# }
# $dryRun = $false

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


# The permissionReference contains the Identification object provided in the retrieve permissions call
try {
    Write-Information "Granting permission to $($pRef.Name) ($($pRef.id)) for $($aRef.userName) ($($aRef.id))"

    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    $group = [PSCustomObject]@{
        schemas = "urn:ietf:params:scim:schemas:core:2.0:Group"
        id      = $pRef.id
        operations = @(
            @{
                op = "add"
                path = "members"
                value = @(
                    @{
                        value = $aRef.id
                        display = $aRef.userName
                    }
                )
            }
        )
    }
    $body = ($group | ConvertTo-Json -Depth 10)

    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/groups/$($pRef.id)"
        Headers = $headers
        Method  = 'PATCH'
        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
    }

    Write-Verbose "Uri: $($splatWebRequest.Uri)"
    Write-Verbose "Body: $($splatWebRequest.Body)"

    if (-Not($dryRun -eq $true)) {
        # No error when user already a member or user doesn't exist
        $addMembership = Invoke-RestMethod @splatWebRequest -Verbose:$false
        Write-Information "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef.userName) ($($aRef.id))"
    }

    $success = $true
    $auditLogs.Add([PSCustomObject]@{
            Action  = "GrantPermission"
            Message = "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef.userName) ($($aRef.id))"
            IsError = $false
        }
    )     
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

        $errorMessage = "Could not create grant $($aRef.userName) ($($aRef.id)) permission to Group $($pRef.Name) ($($pRef.id)). Error: $($errorMessageDetail)"
    }
    else {
        $errorMessage = "Could not create grant $($aRef.userName) ($($aRef.id)) permission to Group $($pRef.Name) ($($pRef.id)). Error: $($ex.Exception.Message)"
    }

    $verboseErrorMessage = "Could not create grant $($aRef.userName) ($($aRef.id)) permission to Group $($pRef.Name) ($($pRef.id)). Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error message: $($ex)"
    Write-Verbose $verboseErrorMessage

    $auditLogs.Add([PSCustomObject]@{
        Message = $errorMessage
        Action  = "GrantPermission"
        IsError = $true
    })
}

#build up result
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    AuditLogs        = $auditLogs
    Account          = $account
}

Write-Output $result | ConvertTo-Json -Depth 10