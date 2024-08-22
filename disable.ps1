#####################################################
# HelloID-Conn-Prov-Target-Zenya-Disable
# Update account
# Version: 2.0.0
#####################################################
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
$correlationField = "Id"
$correlationValue = $actionContext.References.Account.Id

$account = [PSCustomObject]$actionContext.Data
# Remove properties with null-values
$account.PsObject.Properties | ForEach-Object {
    # Remove properties with null-values
    if ($_.Value -eq $null) {
        $account.PsObject.Properties.Remove("$($_.Name)")
    }
}
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

# Define properties to compare for update
$accountPropertiesToCompare = $account.PsObject.Properties.Name
#endRegion account

try {
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

    #region Get account
    # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUserRequest
    $actionMessage = "querying Zenya account where [$($correlationField)] = [$($correlationValue)]"

    $getZenyaAccountSplatParams = @{
        Uri             = "$($actionContext.Configuration.serviceAddress)/scim/users/$($actionContext.References.Account.Id)"
        Headers         = $headers
        Method          = "GET"
        ContentType     = "application/json;charset=utf-8"
        UseBasicParsing = $true
        Verbose         = $false
        ErrorAction     = "Stop"
    }
    
    $getZenyaAccountResponse = Invoke-RestMethod @getZenyaAccountSplatParams
    $correlatedAccount = $getZenyaAccountResponse

    Write-Verbose "Queried Zenya account where [$($correlationField)] = [$($correlationValue)]. Result: $($correlatedAccount | ConvertTo-Json)"
    #endregion Get account

    #region Account
    #region Calulate action
    $actionMessage = "calculating action"
    if (($correlatedAccount | Measure-Object).count -eq 1) {
        $actionMessage = "comparing current account to mapped properties"

        # Create previous account object to compare current data with specified account data - Only keep properties that are mapped
        [PSCustomObject]$previousAccount = $correlatedAccount | Select-Object $account.PSObject.Properties.Name

        # Add email as custom object to account object
        if ($null -ne $correlatedAccount.Emails) {
            $emailsObject = [System.Collections.ArrayList]@()
            foreach ($email in $correlatedAccount.Emails) {
                if ($email.type -eq "work") {
                    [void]$emailsObject.Add("work:$($email.value)")
                }
            }
            $previousAccount | Add-Member -MemberType NoteProperty -Name emails -Value $emailsObject -Force
        }

        # Add department from the extension to previous account object
        if ($true -eq $actionContext.Configuration.setDepartment) {
            $previousAccount | Add-Member -MemberType NoteProperty -Name "Department" -Value $correlatedAccount."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".Department -Force
        }

        # Add manager from the extension to previous account object
        if ($true -eq $actionContext.Configuration.setManager) {
            $previousAccount | Add-Member -MemberType NoteProperty -Name "Manager" -Value $correlatedAccount."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".Manager.Value -Force
        }

        # Set Previous data (if there are no changes between PreviousData and Data, HelloID will log "update finished with no changes")
        $outputContext.PreviousData = $previousAccount

        # Create reference object from previous account
        $accountReferenceObject = [PSCustomObject]@{}
        foreach ($previousAccountProperty in ($previousAccount | Get-Member -MemberType NoteProperty)) {
            # Add property using -join to support array values
            $accountReferenceObject | Add-Member -MemberType NoteProperty -Name $previousAccountProperty.Name.ToLower() -Value ($previousAccount.$($previousAccountProperty.Name) -join ",") -Force
        }

        # Create difference object from mapped properties
        $accountDifferenceObject = [PSCustomObject]@{}
        foreach ($accountProperty in $account.PSObject.Properties) {
            # Add property using -join to support array values
            $accountDifferenceObject | Add-Member -MemberType NoteProperty -Name $accountProperty.Name.ToLower() -Value ($accountProperty.Value -join ",") -Force
        }

        $accountSplatCompareProperties = @{
            ReferenceObject  = $accountReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
            DifferenceObject = $accountDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
        }

        if ($null -ne $accountSplatCompareProperties.ReferenceObject -and $null -ne $accountSplatCompareProperties.DifferenceObject) {
            $accountPropertiesChanged = Compare-Object @accountSplatCompareProperties -PassThru
            $accountOldProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
            $accountNewProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
        }

        if ($accountNewProperties) {
            # Create custom object with old and new values
            $accountChangedPropertiesObject = [PSCustomObject]@{
                OldValues = @{}
                NewValues = @{}
            }

            # Add the old properties to the custom object with old and new values
            foreach ($accountoOldProperty in $accountOldProperties) {
                $accountChangedPropertiesObject.OldValues.$($accountoOldProperty.Name) = $accountoOldProperty.Value
            }

            # Add the new properties to the custom object with old and new values
            foreach ($accountNewProperty in $accountNewProperties) {
                $accountChangedPropertiesObject.NewValues.$($accountNewProperty.Name) = $accountNewProperty.Value
            }

            Write-Verbose "Changed properties: $($accountChangedPropertiesObject | ConvertTo-Json)"

            $actionAccount = "Update"
        }
        else {
            $actionAccount = "NoChanges"
        }            

        Write-Verbose "Compared current account to mapped properties. Result: $actionAccount"
    }
    elseif (($correlatedAccount | Measure-Object).count -eq 0) {
        $actionAccount = "NotFound"
    }
    elseif (($correlatedAccount | Measure-Object).count -gt 1) {
        $actionAccount = "MultipleFound"
    }
    #endregion Calulate action

    #region Process
    switch ($actionAccount) {
        "Update" {
            #region Update account
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchUser
            $actionMessage = "updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create custom account object for update and set with default properties and values
            $updateAccountBody = [PSCustomObject]@{
                id         = $correlatedAccount.id
                operations = @()
            }

            # Add the updated properties to the custom account object for update
            foreach ($accountNewProperty in $accountNewProperties) {
                # Add department as extension property to account body
                if ($accountNewProperty.Name -eq "Department") {
                    $updateAccountBody.operations += @{ 
                        op    = "replace"
                        path  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:Department"
                        value = $accountNewProperty.Value
                    }
                }
                # Add manager as extension property to account body
                elseif ($accountNewProperty.Name -eq "Manager") {
                    $updateAccountBody.operations += @{ 
                        op    = "replace"
                        path  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:Manager"
                        value = $accountNewProperty.Value
                    }
                }
                # Transform and add emails to account body
                elseif ($accountNewProperty.Name -eq "Emails") {
                    foreach ($email in $accountNewProperty.Value) {
                        if ($email.StartsWith("work:")) {
                            $updateAccountBody.operations += @{      
                                op    = "replace"
                                path  = "emails[type eq `"work`"].value"
                                value = $email -replace "work:", ""
                            }
                        }
                    }
                }
                else {
                    $updateAccountBody.operations += @{
                        op    = "replace"
                        path  = $accountNewProperty.name
                        value = $accountNewProperty.value
                    }
                }
            }

            $updateAccountSplatParams = @{
                Uri         = "$($actionContext.Configuration.serviceAddress)/scim/users/$($actionContext.References.Account.Id)"
                Method      = "PATCH"
                Body        = ([System.Text.Encoding]::UTF8.GetBytes(($updateAccountBody | ConvertTo-Json -Depth 10)))
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }
            
            Write-Verbose "SplatParams: $($updateAccountSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $updateAccountSplatParams['Headers'] = $headers

                $updateAccountResponse = Invoke-RestMethod @updateAccountSplatParams

                $outputContext.Data = $account

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Updated account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Updated properties: $($accountChangedPropertiesObject | ConvertTo-Json -Depth 10)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would update account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json). Updated properties: $($accountChangedPropertiesObject | ConvertTo-Json -Depth 10)."
            }
            #endregion Update account

            break
        }

        "NoChanges" {
            #region No changes
            $actionMessage = "skipping updating account"

            $outputContext.Data = $account

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion No changes

            break
        }

        "NotFound" {
            #region No account found
            $actionMessage = "skipping updating account"
        
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No account found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
                    IsError = $true
                })
            #endregion No account found

            break
        }

        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "updating account"

            # Throw terminal error
            throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this to ensure the correlation results in a single unique account."
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
        Write-Warning "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

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