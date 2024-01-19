#####################################################
# HelloID-Conn-Prov-Target-Zenya-Create
#
# Version: 2.0.0
#####################################################

# Set to false at start, at the end, only when no error occurs it is set to true
$outputContext.Success = $false

# AccountReference must have a value for dryRun
$outputContext.AccountReference = "DryRun"

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

$actionContext.DryRun = $false

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
        $headers.Add('Authorization', "$($AccessToken.token_type) $($AccessToken.access_token)")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        Write-Output $headers
    }
    catch {
        throw $_
    }
}
#endregion functions

#region Account mapping
$account = [PSCustomObject]$actionContext.Data

# If option to set department isn't toggled, remove from account object
if ($false -eq $actionContext.Configuration.setDepartment) {
    $account.PSObject.Properties.Remove("Department")
}

# If option to set manager isn't toggled, remove from account object
if ($false -eq $actionContext.Configuration.setManager) {
    $account.PSObject.Properties.Remove("Manager")
}

# Convert active property to boolean
$account.Active = [System.Convert]::ToBoolean($account.Active)
#endregion Account mapping

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

    # Check if we should try to correlate the account
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.accountField
        $correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

        if ($correlationField -eq $null) {
            Write-Warning "Correlation is enabled but not configured correctly."
        }

        # Check if current account exists and and verify if a user must be either [created] or [correlated]
        try {
            $filter = "$($correlationField) eq `"$($correlationValue)`""
            Write-Verbose "Querying account that matches filter [$($filter)]"
            $splatWebRequest = @{
                Uri             = "$baseUrl/scim/users?filter=$([System.Uri]::EscapeDataString($filter))"
                Headers         = $headers
                Method          = 'GET'
                ContentType     = "application/json;charset=utf-8"
                UseBasicParsing = $true
            }

            $correlatedAccount = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

            if (($correlatedAccount | Measure-Object).count -eq 1) {
                $outputContext.AccountReference = [PSCustomObject]@{
                    id       = $correlatedAccount.id
                    userName = $correlatedAccount.userName
                }
                $outputContext.Data.ExternalId = $correlatedAccount.ExternalId
                $outputContext.Data = $correlatedAccount

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                        Message = "Correlated account with username $($correlatedAccount.UserName) on field $($correlationField) with value $($correlationValue)"
                        IsError = $false
                    })

                $outputContext.Success = $True
                $outputContext.AccountCorrelated = $True
            }
            elseif (($correlatedAccount | Measure-Object).count -gt 1) {
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Multiple accounts found that match filter [$($filter)]. Please correct this so the accounts are unique."
                        IsError = $true
                    })
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex

            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
            Write-Verbose "URI: $($splatWebRequest.Uri)"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Error querying account that matches filter [$($filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    IsError = $true
                })

            # Throw terminal error
            throw
        }
    }
    else {
        Write-Warning "Correlation is not enabled."
    }

    # Create account
    if (-Not($outputContext.AccountCorrelated -eq $true)) {
        # Create account
        try {
            # Create account body and set with default properties
            $accountBody = [PSCustomObject]@{
                schemas = @("urn:ietf:params:scim:schemas:core:2.0:User")
            }

            # Add all account properties to account object - Except for Emails, Department and Manager as it is set at as custom object within
            foreach ($accountProperty in $actionContext.Data.PSObject.Properties | Where-Object { $_.Name -ne 'Emails' -and $_.Name -ne 'Department' -and $_.Name -ne 'Manager' }) {
                $accountBody | Add-Member -MemberType NoteProperty -Name $accountProperty.Name -Value $accountProperty.Value -Force
            }

            # Add email as custom object to account object
            if (-not[String]::IsNullOrEmpty($actionContext.Data.Emails)) {
                foreach ($email in $actionContext.Data.Emails) {
                    if ($email.StartsWith("work:")) {
                        $emailsObject = @(
                            [PSCustomObject]@{
                                value   = $email -replace "work:", ""
                                type    = "work"
                                primary = $true
                            }
                        )
                    }
                }
                $accountBody | Add-Member -MemberType NoteProperty -Name emails -Value $emailsObject -Force
            }

            # Add ExtensionObject to account object
            if ("Department" -in $account.PsObject.Properties.Name -or "Manager" -in $account.PsObject.Properties.Name) {
                $extensionObject = [PSCustomObject]@{}

                # Add Department to ExtensionObject of account object
                if ("Department" -in $account.PsObject.Properties.Name) {
                    $departmentObject = $account.Department
                    $extensionObject | Add-Member -MemberType NoteProperty -Name Department -Value $departmentObject -Force
                }

                # Add Manager to ExtensionObject of account object
                if ("Manager" -in $account.PsObject.Properties.Name) {
                    $managerObject = @{
                        value = $mRef.id # Zenya account id
                    }
                    $extensionObject | Add-Member -MemberType NoteProperty -Name Manager -Value $managerObject -Force
                }

                $accountBody | Add-Member -MemberType NoteProperty -Name "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" -Value $extensionObject -Force
            }

            $body = ($accountBody | ConvertTo-Json -Depth 10)
            $splatWebRequest = @{
                Uri             = "$baseUrl/scim/users"
                Headers         = $headers
                Method          = 'POST'
                Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                ContentType     = "application/json;charset=utf-8"
                UseBasicParsing = $true
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "Creating account [$($account.Username)]. Body: $body"

                $createdAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false
                # Set the correct account reference
                $outputContext.AccountReference = [PSCustomObject]@{
                    Id       = $createdAccount.id
                    Username = $createdAccount.userName
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Successfully created account [$($account.Username)]. AccountReference: $($outputContext.AccountReference | ConvertTo-Json -Depth 10)"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would create account [$($account.Username)]. Body: $body"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex

            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
            Write-Verbose "URI: $($splatWebRequest.Uri)"
            Write-Verbose "Body: ($body)"

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Error creating account [$($account.Username)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    IsError = $true
                })

            # Throw terminal error
            throw
        }
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

    # Set data with account object
    $outputContext.Data = $account
}