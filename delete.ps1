#####################################################
# HelloID-Conn-Prov-Target-Zenya-Delete
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

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

# Account mapping


# Troubleshooting
# $aRef = @{
#    userName = "TestHelloID@enyoi.onmicrosoft.com"
#    id       = "64e1c737-0274-4ba6-ae12-201edbe77d99"
# }
# $dryRun = $false

#region functions
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
            "grant_type" =  'client_credentials'
            "client_id" =  $ClientId
            "client_secret" = $ClientSecret
            "token_expiration_disabled" =  $false
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
#endregion functions

try {
    if ($null -eq $aRef.id) {
        throw "No Account Reference found in HelloID"
    }

    # Get current user
    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose "Account lookup based on id [$($aRef.id)]"
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/users/$($aRef.id)"
        Headers = $headers
        Method  = 'GET'
    }
    $currentUser = (Invoke-RestMethod @splatWebRequest -Verbose:$false)

    if($null -eq $currentUser.id){
        throw "No User found in Zenya with id [$($aRef.id)]"
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "Delete Zenya account [$($account.userName)], will be executed during enforcement"
            })
    }

    if (-not($dryRun -eq $true)) {
        $bodyUpdate = [PSCustomObject]@{
            id = $currentUser.id
        }
        $body = $bodyUpdate | ConvertTo-Json -Depth 10

        Write-Verbose "Deleting Zenya account $($currentUser.userName) ($($currentUser.id))"
        Write-Verbose "Body: $body"
        $splatWebRequest = @{
            Uri     = "$baseUrl/scim/users/$($currentUser.id)"
            Headers = $headers
            Method  = 'DELETE'
            Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
        }
        $deletedUser = Invoke-RestMethod @splatWebRequest -Verbose:$false

        $auditLogs.Add([PSCustomObject]@{
                Action = "DeleteAccount"
                Message = "Delete account was successful for account $($aRef.userName) ($($aRef.id))"
                IsError = $false
            })
        $success = $true
    }
} catch {
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
        
        $errorMessage = "Could not delete enya account $($aref.username) ($($aRef.id)). Error: $($errorMessageDetail)"
    }
    else {
        $errorMessage = "Could not delete enya account $($aref.username) ($($aRef.id)). Error: $($ex.Exception.Message)"
    }

    $verboseErrorMessage = "Could not delete Zenya account $($aref.username) ($($aRef.id)). Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error message: $($ex)"
    Write-Verbose $verboseErrorMessage
  
    $auditLogs.Add([PSCustomObject]@{
            Action = "DeleteAccount"
            Message = $errorMessage
            IsError = $true
        })
} finally {
    $result = [PSCustomObject]@{
        Success   = $success
        Account   = $account
        Auditlogs = $auditLogs

        # Optionally return data for use in other systems
        ExportData       = [PSCustomObject]@{
            id          = $aRef.id;
            username    = $aRef.username;
        }
    }; 
    Write-Output $result | ConvertTo-Json -Depth 10
}