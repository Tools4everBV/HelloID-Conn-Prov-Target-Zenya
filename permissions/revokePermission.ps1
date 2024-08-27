#####################################################
# HelloID-Conn-Prov-Target-Zenya-Permissions-Revoke
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
        $errorMessage = ""

        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.detail) {
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '{(.*)}').Value
                if ($null -ne $errorObjectDetail) {
                    try {
                        $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction Stop
                        if ($null -ne $errorDetailConverted) {
                            if ($null -ne $errorDetailConverted.Error.Message) {
                                $errorMessage = $errorMessage + $errorDetailConverted.Error.Message
                            }
                            if ($null -ne $errorDetailConverted.title) {
                                $errorMessage = $errorMessage + $errorDetailConverted.title
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

                if ($null -ne $errorObjectConverted.status) {
                    $errorMessage = $errorMessage + " (" + $errorObjectConverted.status + ")"
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
            $errorMessage.AuditErrorMessage = (Resolve-ZenyaErrorMessage $ErrorObject.ErrorDetails.Message) + ". Response Status: $($ErrorObject.Exception.Response.StatusCode)."
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
    #region Verify account reference
    $actionMessage = "verifying account reference"
    
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference

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

    # Get current account
    try {
        Write-Verbose "Querying account with id [$($actionContext.References.Account)]"
        $splatWebRequest = @{
            Uri             = "$baseUrl/scim/users/$($actionContext.References.Account)"
            Headers         = $headers
            Method          = 'GET'
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
        }

        $currentAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false

        if (($currentAccount | Measure-Object).count -gt 1) {
            throw "Multiple accounts found with id [$($actionContext.References.Account)]. Please correct this so the accounts are unique."
        }
        elseif (($currentAccount | Measure-Object).count -eq 0) {
            throw "No account found with id [$($actionContext.References.Account)]."
        }
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex
    
        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        Write-Verbose "URI: $($splatWebRequest.Uri)"

        if ($errorMessage.AuditErrorMessage -Like "*No account found*" -or $errorMessage.AuditErrorMessage -Like "*(404) Not Found.*" -or $errorMessage.AuditErrorMessage -Like "*User not found*") {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped revoking permission for account with id [$($actionContext.References.Account)]. Reason: No longer exists"
                    IsError = $false
                })
        }
        else {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Error querying account with id [$($actionContext.References.Account)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    IsError = $true
                })

            # Throw terminal error
            throw
        }
    }

    # Revoke permission
    try {
        Write-Verbose "Revoking permission to $($actionContext.References.Permission.Name) ($($actionContext.References.Permission.id)) for $($currentAccount.userName) ($($currentAccount.id))"

        # Create permission body
        $permissionBody = [PSCustomObject]@{
            schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
            id         = $actionContext.References.Permission.id
            operations = @(
                @{
                    op    = "remove"
                    path  = "members"
                    value = @(
                        @{
                            value   = $currentAccount.id
                            display = $currentAccount.userName
                        }
                    )
                }
            )
        }

        $body = ($permissionBody | ConvertTo-Json -Depth 10)
        $splatWebRequest = @{
            Uri             = "$baseUrl/scim/groups/$($actionContext.References.Permission.Id)"
            Headers         = $headers
            Method          = 'PATCH'
            Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
        }

        if (-Not($actionContext.DryRun -eq $true)) {
            Write-Verbose "Revoking permission: [$($actionContext.References.Permission.Name) ($($actionContext.References.Permission.id))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"

            $revokePermission = Invoke-RestMethod @splatWebRequest -Verbose:$false

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Successfully revoked permission: [$($actionContext.References.Permission.Name) ($($actionContext.References.Permission.id))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
                    IsError = $false
                })
        }
        else {
            Write-Warning "DryRun: Would revoke permission: [$($actionContext.References.Permission.Name) ($($actionContext.References.Permission.id))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
        }
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        Write-Verbose "URI: $($splatWebRequest.Uri)"
        Write-Verbose "Body: $($body)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error revoking permission: [$($actionContext.References.Permission.Name) ($($actionContext.References.Permission.id))] to account: [$($currentAccount.userName) ($($currentAccount.id))]. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Throw terminal error
        throw
    }
}
catch {
    $ex = $PSItem
    Write-Warning "Terminal error occurred. Error Message: $($ex.Exception.Message)"
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}