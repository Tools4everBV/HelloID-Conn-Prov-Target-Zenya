#####################################################
# HelloID-Conn-Prov-Target-Zenya-Permissions-Groups
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json

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
        } | ConvertTo-Json
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
    # Get groups
    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose 'Retrieve Group list from Zenya'
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/groups"
        Headers = $headers
        Method  = 'GET'
    }
    $groupList = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

    Write-Information "Successfully retrieved Group list from Zenya. Result count: $($groupList.id.Count)"
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

        $errorMessage = "Could not retrieve Group list from Zenya. Error: $($errorMessageDetail)"
    }
    else {
        $errorMessage = "Could not retrieve Group list from Zenya. Error: $($ex.Exception.Message)"
    }

    $verboseErrorMessage = "Could not retrieve Group list from Zenya. Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error message: $($ex)"
    Write-Verbose $verboseErrorMessage

    throw $errorMessage
}

foreach ($group in $groupList) {
    $returnObject = @{
        DisplayName    = "Group - $($group.displayName)";
        Identification = @{
            id   = $group.id
            Name = $group.displayName
            Type = "Group"
        }
    };

    Write-Output $returnObject | ConvertTo-Json -Depth 10
}