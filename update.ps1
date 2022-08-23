#####################################################
# HelloID-Conn-Prov-Target-Zenya-Update
#
# Version: 1.1.2
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $AccountReference | ConvertFrom-Json
$success = $true # Set to true at start, because only when an error occurs it is set to false
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
$account = [PSCustomObject]@{
    schemas           = "urn:ietf:params:scim:schemas:core:2.0:User"
    externalId        = $p.ExternalId
    userName          = $p.Accounts.MicrosoftActiveDirectory.UserPrincipalName
    displayname       = $p.Accounts.MicrosoftActiveDirectory.DisplayName
    preferredLanguage = "nl-NL"
    emails            = @(
        [PSCustomObject]@{
            value   = $p.Accounts.MicrosoftActiveDirectory.mail
            type    = "work"
            primary = $true
        }
    )
}

# Troubleshooting
# $aRef = @{
#    userName = "TestHelloID@enyoi.onmicrosoft.com"
#    id       = "64e1c737-0274-4ba6-ae12-201edbe77d99"
# }
# $account = [PSCustomObject]@{
#     schemas           = "urn:ietf:params:scim:schemas:core:2.0:User"
#     externalId        = "99999999"
#     userName          = "TestHelloID@enyoi.onmicrosoft.com"
#     displayname       = "Test HelloID"
#     preferredLanguage = "nl-NL"
#     emails            = @(
#         [PSCustomObject]@{
#             value   = "T.HelloID@enyoi.onmicrosoft.com"
#             type    = "work"
#             primary = $true
#         }
#     )
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

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

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
#endregion functions

# Get current Zenya account
try {
    if ($null -eq $aRef.id) {
        throw "No Account Reference found in HelloID"
    }

    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose "Querying Zenya account with id $($aRef.id)"
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/users/$($aRef.id)"
        Headers = $headers
        Method  = 'GET'
    }
    $currentUser = $null
    $currentUser = Invoke-RestMethod @splatWebRequest -Verbose:$false

    if ($null -eq $currentUser.id) {
        throw "No User found in Zenya with id $($aRef.id)"
    }

    #Verify if the account must be updated
    $splatCompareProperties = @{
        ReferenceObject  = @( ($currentUser | Select-Object *, @{ Name = 'emailValues'; Expression = { $_.emails } } -ExcludeProperty id, meta).PSObject.Properties )
        DifferenceObject = @( ($account | Select-Object *, @{ Name = 'emailValues'; Expression = { $_.emails } } -ExcludeProperty schemas).PSObject.Properties )
    }
    $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where( { $_.SideIndicator -eq '=>' })
    if ($propertiesChanged) {
        Write-Verbose "Account property(s) required to update: [$($propertiesChanged.name -join ",")]"
        $updateAction = 'Update'
    }
    else {
        $updateAction = 'NoChanges'
    }

}
catch {
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    if ($auditErrorMessage -Like "No User found in Zenya with id $($aRef.id)" -or $auditErrorMessage -Like "*(404) Not Found.*" -or $auditErrorMessage -Like "*User not found*") {
        if (-Not($dryRun -eq $True)) {
            $success = $false
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "UpdateAccount"
                    Message = "No Zenya account found with id $($aRef.id). Possibly deleted."
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: No Zenya account found with id $($aRef.id). Possibly deleted."
        }        
    }
    else {
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "UpdateAccount"
                Message = "Error querying Zenya account with id $($aRef.id). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

# Update Zenya account
if ($null -ne $currentUser.id) {
    switch ($updateAction) {
        'Update' {
            try {
                Write-Verbose "Updating Zenya account $($currentUser.userName) ($($currentUser.id))"

                $bodyUpdate = [PSCustomObject]@{
                    id         = $currentUser.id
                    operations = @()
                }

                foreach ($property in $propertiesChanged) {
                    # Additional mapping for email object
                    if ($property.name -eq 'emailValues') {
                        $bodyUpdate.operations += @{
                            # op = "replace"
                            # path = 'emails[type eq "work"].value'
                            # value = $email

                            op    = "replace"
                            path  = "emails[type eq `"$($property.Value.type)`"].value"
                            value = $property.value.value
                        }
                    }
                    else {
                        $bodyUpdate.operations += @{
                            op    = "replace"
                            path  = $property.name
                            value = $property.value
                        }
                    }
                }
                $body = ($bodyUpdate | ConvertTo-Json -Depth 10)

                $splatWebRequest = @{
                    Uri     = "$baseUrl/scim/users/$($currentUser.id)"
                    Headers = $headers
                    Method  = 'PATCH'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
                }

                if (-not($dryRun -eq $true)) {
                    $updatedUser = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $aRef = [PSCustomObject]@{
                        id       = $updatedUser.id
                        userName = $updatedUser.userName
                    }

                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "UpdateAccount"
                            Message = "Successfully updated Zenya account $($aRef.userName) ($($aRef.id))"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would update Zenya account $($currentUser.userName) ($($currentUser.id))"
                }
                break
            }
            catch {
                $ex = $PSItem
                if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
                    $errorObject = Resolve-HTTPError -Error $ex

                    $verboseErrorMessage = $errorObject.ErrorMessage

                    $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $errorObject.ErrorMessage
                }

                # If error message empty, fall back on $ex.Exception.Message
                if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
                    $verboseErrorMessage = $ex.Exception.Message
                }
                if ([String]::IsNullOrEmpty($auditErrorMessage)) {
                    $auditErrorMessage = $ex.Exception.Message
                }

                Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                
                $success = $false  
                $auditLogs.Add([PSCustomObject]@{
                        Action  = "UpdateAccount"
                        Message = "Error updating Zenya account $($currentUser.userName) ($($currentUser.id)). Error Message: $auditErrorMessage"
                        IsError = $True
                    })
            }
        }
        'NoChanges' {
            Write-Verbose "No changes to Zenya account $($currentUser.userName) ($($currentUser.id))"

            if (-not($dryRun -eq $true)) {
                $aRef = [PSCustomObject]@{
                    id       = $currentUser.id
                    userName = $currentUser.userName
                }

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "UpdateAccount"
                        Message = "Successfully updated Zenya account $($aRef.userName) ($($aRef.id)) (No Changes needed)"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: No changes to Zenya account $($currentUser.userName) ($($currentUser.id))"
            }
            break
        }
    }
}

# Send results
$result = [PSCustomObject]@{
    Success    = $success
    Account    = $account
    Auditlogs  = $auditLogs

    # Optionally return data for use in other systems
    ExportData = [PSCustomObject]@{
        id       = $aRef.id
        userName = $aRef.userName
    }
} 
Write-Output $result | ConvertTo-Json -Depth 10