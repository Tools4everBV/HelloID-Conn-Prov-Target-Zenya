#####################################################
# HelloID-Conn-Prov-Target-Zenya-Disable
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

    # Get current account
    try {
        Write-Verbose "Querying account with id [$($actionContext.References.Account.Id)]"
        $splatWebRequest = @{
            Uri             = "$baseUrl/scim/users/$($actionContext.References.Account.Id)"
            Headers         = $headers
            Method          = 'GET'
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
        }

        $currentAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false

        if (($currentAccount | Measure-Object).count -gt 1) {
            throw "Multiple accounts found with id [$($actionContext.References.Account.Id)]. Please correct this so the accounts are unique."
        }
        elseif (($currentAccount | Measure-Object).count -eq 0) {
            throw "No account found with id [$($actionContext.References.Account.Id)]."
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
                    Message = "Skipped updating account with id [$($actionContext.References.Account.Id)]. Reason: No longer exists"
                    IsError = $false
                })
        }
        else {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Error querying account with id [$($actionContext.References.Account.Id)]. Error Message: $($errorMessage.AuditErrorMessage)"
                    IsError = $true
                })

            # Throw terminal error
            throw
        }
    }

    # Calculate changes
    try {
        if (($currentAccount | Measure-Object).count -eq 1) {
            Write-Verbose "Calculating changes"
            
            # Create previous account object to compare current data with specified account data - Only keep properties that are mapped
            [PSCustomObject]$previousAccount = $currentAccount | Select-Object $account.PSObject.Properties.Name

            # Add email as custom object to account object
            if ($null -ne $currentAccount.Emails) {
                $emailsObject = [System.Collections.ArrayList]@()
                foreach ($email in $currentAccount.Emails) {
                    if ($email.type -eq "work") {
                        [void]$emailsObject.Add("work:$($email.value)")
                    }
                }
                $previousAccount | Add-Member -MemberType NoteProperty -Name emails -Value $emailsObject -Force
            }

            # Add department from the extension to previous account object
            if ($true -eq $actionContext.Configuration.setDepartment) {
                $currentAccountDepartmentObject = $currentAccount."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".Department
                $previousAccount | Add-Member -MemberType NoteProperty -Name "Department" -Value $currentAccountDepartmentObject -Force
            }

            # Add manager from the extension to previous account object
            if ($true -eq $actionContext.Configuration.setManager) {
                $currentAccountManagerObject = @{
                    value = $currentAccount."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".Manager.Value
                }
                $previousAccount | Add-Member -MemberType NoteProperty -Name "Manager" -Value $currentAccountManagerObject -Force
            }

            # Calculate changes between current data and provided data
            # Create reference object with lowercase property names
            $referenceObject = [PSCustomObject]@{}
            foreach ($property in $previousAccount.PSObject.Properties) {
                $referenceObject  | Add-Member -MemberType NoteProperty -Name $property.Name.ToLower() -Value $property.Value
            }

            # Create difference object with lowercase property names
            $differenceObject = [PSCustomObject]@{}
            foreach ($property in $account.PSObject.Properties) {
                $differenceObject | Add-Member -MemberType NoteProperty -Name $property.Name.ToLower() -Value $property.Value
            }
            
            $splatCompareProperties = @{
                ReferenceObject  = @($referenceObject.PSObject.Properties)
                DifferenceObject = @($differenceObject.PSObject.Properties)
            }

            $changedProperties = $null
            $changedProperties = (Compare-Object @splatCompareProperties -PassThru)
            $oldProperties = $changedProperties.Where( { $_.SideIndicator -eq '<=' })
            $newProperties = $changedProperties.Where( { $_.SideIndicator -eq '=>' })

            if (($newProperties | Measure-Object).Count -ge 1) {
                Write-Warning "Changed properties: $($changedProperties | ConvertTo-Json)."

                $updateAction = 'Update'
            }
            else {
                Write-Verbose "No changed properties."

                $updateAction = 'NoChanges'
            }

            Write-Verbose "Successfully calculated changes."
        }
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        Write-Verbose "URI: $($splatWebRequest.Uri)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error calculating changes. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Throw terminal error
        throw
    }

    # Update account
    switch ($updateAction) {
        'Update' {
            try {
                # Create custom object with old and new values
                $changedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }

                # Add the old properties to the custom object with old and new values
                foreach ($oldProperty in ($oldProperties | Where-Object { $_.Name -in $newProperties.Name })) {
                    $changedPropertiesObject.OldValues.$($oldProperty.Name) = $oldProperty.Value
                }

                # Add the new properties to the custom object with old and new values
                foreach ($newProperty in $newProperties) {
                    $changedPropertiesObject.NewValues.$($newProperty.Name) = $newProperty.Value
                }
                Write-Verbose "Changed properties: $($changedPropertiesObject | ConvertTo-Json)"

                # Create account body and set with default properties and values
                $accountBody = [PSCustomObject]@{
                    id         = $currentAccount.id
                    operations = @()
                }

                # Add the updated properties to account body
                foreach ($newProperty in $newProperties) {
                    # Add department as extension property to account body
                    if ($newProperty.Name -eq "Department") {
                        $accountBody.operations += @{ 
                            op    = "replace"
                            path  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:Department"
                            value = $newProperty.Value
                        }
                    }
                    # Add manager as extension property to account body
                    elseif ($newProperty.Name -eq "Manager") {
                        $accountBody.operations += @{ 
                            op    = "replace"
                            path  = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:Manager"
                            value = $newProperty.Value
                        }
                    }
                    # Transform and add emails to account body
                    elseif ($newProperty.Name -eq "Emails") {
                        foreach ($email in $newProperty.Value) {
                            if ($email.StartsWith("work:")) {
                                $accountBody.operations += @{      
                                    op    = "replace"
                                    path  = "emails[type eq `"work`"].value"
                                    value = $email -replace "work:", ""
                                }
                            }
                        }
                    }
                    else {
                        $accountBody.operations += @{
                            op    = "replace"
                            path  = $newProperty.name
                            value = $newProperty.value
                        }
                    }
                }

                $body = ($accountBody | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri             = "$baseUrl/scim/users/$($currentAccount.Id)"
                    Headers         = $headers
                    Method          = 'PATCH'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Disabling account [$($currentAccount.Username)]. AccountReference: $($actionContext.References.Account | ConvertTo-Json -Depth 10). Body: $body"
        
                    $updatedAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    # Set the correct account reference
                    $outputContext.AccountReference = [PSCustomObject]@{
                        Id       = $updatedAccount.id
                        Username = $updatedAccount.userName
                    }
        
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Successfully disabled account [$($currentAccount.Username)]. AccountReference: $($outputContext.AccountReference | ConvertTo-Json -Depth 10). Old values: $($changedPropertiesObject.oldValues | ConvertTo-Json -Depth 10). New values: $($changedPropertiesObject.newValues | ConvertTo-Json -Depth 10)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would disable account [$($currentAccount.Username)]. AccountReference: $($actionContext.References.Account | ConvertTo-Json -Depth 10). Old values: $($changedPropertiesObject.oldValues | ConvertTo-Json -Depth 10). New values: $($changedPropertiesObject.newValues | ConvertTo-Json -Depth 10)"
                }
                break
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                Write-Verbose "URI: $($splatWebRequest.Uri)"
                Write-Verbose "Body: $($body)"
        
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Error disabling account [$($currentAccount.Username)]. AccountReference: $($actionContext.References.Account | ConvertTo-Json -Depth 10). Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $true
                    })
        
                # Throw terminal error
                throw
            }
        }
        'NoChanges' {
            if (-not($dryRun -eq $true)) {
                Write-Verbose "Skipped disabling account [$($account.Username)]. Reason: No changes"
            }
            else {
                Write-Warning "DryRun: Would skip disabling account [$($account.Username)]. Reason: No changes"
            }
            break
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