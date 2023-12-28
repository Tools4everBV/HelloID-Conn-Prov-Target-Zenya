#####################################################
# HelloID-Conn-Prov-Target-Zenya-Permissions-Retrieve
#
# Version: 2.0.0
#####################################################

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Zenya Scim endpoints
$baseUrl = $actionContext.Configuration.serviceAddress
$clientId = $actionContext.Configuration.clientId
$clientSecret = $actionContext.Configuration.clientSecret

#region functions
function Resolve-ZenyaErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.detail) {
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '{(.*)}').Value
                if ($null -ne $errorObjectDetail) {
                    try {
                        $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction Stop

                        if ($null -ne $errorDetailConverted) {
                            if ($null -ne $errorDetailConverted.Error.Message) {
                                $errorMessage = $errorDetailConverted.Error.Message
                            }
                        }
                    }
                    catch {
                        $errorMessage = $errorObjectDetail
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.detail
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        try {
            $errorMessage.VerboseErrorMessage = $ErrorObject.ErrorDetails.Message
            $errorMessage.AuditErrorMessage = Resolve-ZenyaErrorMessage $ErrorObject.ErrorDetails.Message
        }
        catch {
            Write-Verbose "Error resolving Zenya error message, using default Powershell error message"
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

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
        [void]$headers.Add('Authorization', "$($AccessToken.token_type) $($AccessToken.access_token)")
        [void]$headers.Add('Accept', 'application/json')
        [void]$headers.Add('Content-Type', 'application/json')
        Write-Output $headers
    }
    catch {
        throw $_
    }
}
#endregion functions

try {
    # Create authorization headers
    try {
        $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error creating authorization headers. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Throw terminal error
        throw
    }

    # Get groups
    try {
        Write-Verbose "Querying groups"

        $groups = [System.Collections.ArrayList]::new()
        $skip = 0
        $take = 100
        do {
            $splatWebRequest = @{
                Uri             = "$baseUrl/scim/groups?startIndex=$($skip)&count=$($take)"
                Headers         = $headers
                Method          = 'GET'
                ContentType     = "application/json;charset=utf-8"
                UseBasicParsing = $true
            }

            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
            if ($response.Resources -is [array]) {
                [void]$groups.AddRange($response.Resources)
            }
            else {
                [void]$groups.Add($response.Resources)
            }

            $skip += $pageSize
        } while (($groups | Measure-Object).Count -lt $response.totalResults)

        Write-Information "Successfully queried groups. Result count: $(($groups | Measure-Object).Count)"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        Write-Verbose "URI: $($splatWebRequest.Uri)"

        # Throw terminal error
        throw "Error querying groups. Error Message: $($errorMessage.AuditErrorMessage)"
    }
}
finally {
    # Send results
    foreach ($group in $groups) {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Group - $($group.DisplayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        $permission = @{
            DisplayName    = $displayName
            Identification = @{
                id   = $group.id
                Name = $group.displayName
                Type = "Group"
            }
        }

        $outputContext.Permissions.Add($permission)
    }
}