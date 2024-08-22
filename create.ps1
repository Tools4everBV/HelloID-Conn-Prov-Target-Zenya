#################################################
# HelloID-Conn-Prov-Target-Zenya-Create
# Correlate to or create account
# PowerShell V2
#################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-ZenyaError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorObjectConverted = $httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.detail) {
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '{(.*)}').Value
                if ($null -ne $errorObjectDetail) {
                    try {
                        $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction Stop
                        if ($null -ne $errorDetailConverted) {
                            if ($null -ne $errorDetailConverted.Error.Message) {
                                $httpErrorObj.FriendlyMessage = $errorMessage + $errorDetailConverted.Error.Message
                            }
                            if ($null -ne $errorDetailConverted.title) {
                                $httpErrorObj.FriendlyMessage = $errorMessage + $errorDetailConverted.title
                            }
                        }
                    }
                    catch {
                        $httpErrorObj.FriendlyMessage = $errorObjectDetail
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.detail
                }

                if ($null -ne $errorObjectConverted.status) {
                    $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + " (" + $errorObjectConverted.status + ")"
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $ErrorObject
        }
        Write-Output $httpErrorObj
    }
}

function Convert-StringToBoolean($obj) {
    if ($obj -is [PSCustomObject]) {
        foreach ($property in $obj.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string]) {
                $lowercaseValue = $value.ToLower()
                if ($lowercaseValue -eq "true") {
                    $obj.$($property.Name) = $true
                }
                elseif ($lowercaseValue -eq "false") {
                    $obj.$($property.Name) = $false
                }
            }
            elseif ($value -is [PSCustomObject] -or $value -is [System.Collections.IDictionary]) {
                $obj.$($property.Name) = Convert-StringToBoolean $value
            }
            elseif ($value -is [System.Collections.IList]) {
                for ($i = 0; $i -lt $value.Count; $i++) {
                    $value[$i] = Convert-StringToBoolean $value[$i]
                }
                $obj.$($property.Name) = $value
            }
        }
    }
    return $obj
}
#endregion functions

#region account
# Define correlation
$correlationField = $actionContext.CorrelationConfiguration.accountField
$correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

$account = [PSCustomObject]$actionContext.Data

# Convert the properties containing "TRUE" or "FALSE" to boolean
$account = Convert-StringToBoolean $account

# If option to set department isn't toggled, remove from account object
if ($false -eq $actionContext.Configuration.setDepartment) {
    $account.PSObject.Properties.Remove("Department")
}

# If option to set manager isn't toggled, remove from account object
if ($false -eq $actionContext.Configuration.setManager) {
    $account.PSObject.Properties.Remove("Manager")
}
else {
    $account | Add-Member -MemberType NoteProperty -Name Manager -Value $actionContext.References.ManagerAccount.Id -Force
}
#endRegion account

try {
    #region Verify correlation configuration and properties
    $actionMessage = "verifying correlation configuration and properties"

    if ($actionContext.CorrelationConfiguration.Enabled -eq $true) {
        if ([string]::IsNullOrEmpty($correlationField)) {
            throw "Correlation is enabled but not configured correctly."
        }
    
        if ([string]::IsNullOrEmpty($correlationValue)) {
            throw "The correlation value for [$correlationField] is empty. This is likely a mapping issue."
        }
    }
    else {
        Write-Warning "Correlation is disabled."
    }
    #endregion Verify correlation configuration and properties

    #region Create access token
    $actionMessage = "creating access token"

    $createAccessTokenBody = @{
        grant_type                = "client_credentials"
        client_id                 = $actionContext.Configuration.clientId
        client_secret             = $actionContext.Configuration.clientSecret
        token_expiration_disabled = $false
    }

    $createAccessTokenSplatParams = @{
        Uri             = "$($actionContext.Configuration.serviceAddress)/oauth/token"
        Headers         = $headers
        Method          = "POST"
        ContentType     = "application/json"
        UseBasicParsing = $true
        Body            = ($createAccessTokenBody | ConvertTo-Json)
        Verbose         = $false
        ErrorAction     = "Stop"
    }

    $createAccessTokenResonse = Invoke-RestMethod @createAccessTokenSplatParams

    Write-Verbose "Created access token. Result: $($createAccessTokenResonse | ConvertTo-Json)"
    #endregion Create access token

    #region Create headers
    $actionMessage = "creating headers"

    $headers = @{
        "Authorization" = "$($createAccessTokenResonse.token_type) $($createAccessTokenResonse.access_token)"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
    }

    Write-Verbose "Created headers. Result: $($headers | ConvertTo-Json)."
    #endregion Create headers

    if ($actionContext.CorrelationConfiguration.Enabled) {
        #region Get account
        # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUsersRequest
        $actionMessage = "querying Zenya account where [$($correlationField)] = [$($correlationValue)]"

        $filter = "$($correlationField) eq `"$($correlationValue)`""
        $getZenyaAccountSplatParams = @{
            Uri             = "$($actionContext.Configuration.serviceAddress)/scim/users?filter=$([System.Uri]::EscapeDataString($filter))"
            Headers         = $headers
            Method          = "GET"
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
            Verbose         = $false
            ErrorAction     = "Stop"
        }
    
        $getZenyaAccountResponse = Invoke-RestMethod @getZenyaAccountSplatParams
        $correlatedAccount = $getZenyaAccountResponse.resources

        Write-Verbose "Queried Zenya account where [$($correlationField)] = [$($correlationValue)]. Result: $($correlatedAccount | ConvertTo-Json)"
        #endregion Get account
    }

    #region Account
    #region Calulate action
    $actionMessage = "calculating action"
    if (($correlatedAccount | Measure-Object).count -eq 1) {
        $actionAccount = "Correlate"
    }
    elseif (($correlatedAccount | Measure-Object).count -eq 1) {
        $actionAccount = "Create"
    }
    elseif (($correlatedAccount | Measure-Object).count -gt 1) {
        $actionAccount = "MultipleFound"
    }
    #endregion Calulate action

    #region Process
    switch ($actionAccount) {
        "Correlate" {
            #region Correlate account
            $actionMessage = "correlating to account"
    
            $outputContext.AccountReference = [PSCustomObject]@{
                id       = $correlatedAccount.id
                userName = $correlatedAccount.userName
            }
            $outputContext.Data = $correlatedAccount
    
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                    Message = "Correlated to account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json) on [$($correlationField)] = [$($correlationValue)]."
                    IsError = $false
                })
    
            $outputContext.AccountCorrelated = $true
            #endregion Correlate account
    
            break
        }

        "Create" {
            #region Create account                  
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PostUserRequest
            $actionMessage = "creating account with DisplayName [$($account.DisplayName)] and UserName [$($account.UserName)]"

            # Create account body and set with default properties
            $createAccountBody = [PSCustomObject]@{
                schemas = @("urn:ietf:params:scim:schemas:core:2.0:User")
            }

            # Add all account properties to account object
            # Ecluded the fields: Emails, Department and Manager. As they are set at as custom object
            $excludedField = @("Emails", "Department", "Manager")
            foreach ($accountProperty in $account.PsObject.Properties | Where-Object { $_.Name -notin $excludedField }) {
                $createAccountBody | Add-Member -MemberType NoteProperty -Name $accountProperty.Name -Value $accountProperty.Value -Force
            }

            # Add email as custom object to account object
            if (-not[String]::IsNullOrEmpty($account.Emails)) {
                foreach ($email in $account.Emails) {
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
                $createAccountBody | Add-Member -MemberType NoteProperty -Name emails -Value $emailsObject -Force
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
                        value = $account.Manager # Zenya account id
                    }
                    $extensionObject | Add-Member -MemberType NoteProperty -Name Manager -Value $managerObject -Force
                }

                $createAccountBody | Add-Member -MemberType NoteProperty -Name "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User" -Value $extensionObject -Force
            }

            $createAccountSplatParams = @{
                Uri         = "$($actionContext.Configuration.serviceAddress)/v1.0/users"
                Method      = "POST"
                Body        = ($createAccountBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Verbose "SplatParams: $($createAccountSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $createAccountSplatParams['Headers'] = $headers

                $createAccountResponse = Invoke-RestMethod @createAccountSplatParams
                $createdAccount = $createAccountResponse

                $outputContext.AccountReference = [PSCustomObject]@{
                    id       = $createdAccount.id
                    userName = $createdAccount.userName
                }
                $outputContext.Data = $createdAccount

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Created account with DisplayName [$($account.DisplayName)] and UserName [$($account.UserName)] with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would create account with DisplayName [$($account.DisplayName)] and UserName [$($account.UserName)]."
            }
            #endregion Create account
                        
            break
        }
    
        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "correlating to account"
    
            # Throw terminal error
            throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
            #endregion Multiple accounts found
    
            break
        }
    }
    #endregion Process
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-ZenyaError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }

    # Check if accountreference is set, if not set, set this with default value as this must contain a value
    if ([String]::IsNullOrEmpty($outputContext.AccountReference) -and $actionContext.DryRun -eq $true) {
        $outputContext.AccountReference = "DryRun: Currently not available"
    }
}