#####################################################
# HelloID-Conn-Prov-Target-Zenya-Create
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
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

# Set to true if accounts in the target system must be updated
$updateAccount = $true

# Account mapping
$account = [PSCustomObject]@{
    schemas = "urn:ietf:params:scim:schemas:core:2.0:User"
    externalId = $p.ExternalId
    userName = $p.Accounts.MicrosoftActiveDirectory.UserPrincipalName
    displayname = $p.Accounts.MicrosoftActiveDirectory.DisplayName
    preferredLanguage = "nl-NL"
    active = $False
    emails = [PSCustomObject]@{
            value = $p.Accounts.MicrosoftActiveDirectory.mail
            type = "work"
            primary = $True
    }
}

# Troubleshooting
# $account = [PSCustomObject]@{
#     schemas = "urn:ietf:params:scim:schemas:core:2.0:User"
#     externalId = "99999999"
#     userName = "TestHelloID@enyoi.onmicrosoft.com"
#     displayname = "Test HelloID"
#     preferredLanguage = "nl-NL"
#     active = $False
#     emails = @(
#         [PSCustomObject]@{
#             value = "TestHelloID@enyoi.onmicrosoft.com"
#             type = "work"
#             primary = $True
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

# Begin
try {
    # Verify if a user must be either [created], [updated and correlated] or just [correlated]
    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose "Account lookup based on userName [$($account.userName)]"
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/users?filter=userName%20eq%20%22$($account.userName)%22"
        Headers = $headers
        Method  = 'GET'
    }
    $currentUser = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

    if($null -eq $currentUser.id){
        $action = 'Create'
    }
    elseif ($updateAccount -eq $true) {
        $action = 'Update-Correlate'

        #Verify if the account must be updated
        $splatCompareProperties = @{
            ReferenceObject  = @( ($currentUser | Select-Object *,@{ Name = 'emailValues';  Expression = { $_.emails} } -ExcludeProperty id,meta).PSObject.Properties )
            DifferenceObject = @( ($account | Select-Object *,@{ Name = 'emailValues';  Expression = { $_.emails} } -ExcludeProperty schemas).PSObject.Properties )
        }
        $propertiesChanged = (Compare-Object @splatCompareProperties -PassThru).Where( { $_.SideIndicator -eq '=>' })
        if ($propertiesChanged) {
            Write-Verbose "Account property(s) required to update: [$($propertiesChanged.name -join ",")]"
            $updateAction = 'Update'
        } else {
            $updateAction = 'NoChanges'
        }
    }
    else {
        $action = 'Correlate'
    }

    # Add an auditMessage showing what will happen during enforcement
    if ($dryRun -eq $true) {
        $auditLogs.Add([PSCustomObject]@{
                Message = "$action Zenya account [$($account.userName)], will be executed during enforcement"
            })
    }

    # Process
    if (-not($dryRun -eq $true)) {
        switch ($action) {
            'Create' {
                Write-Verbose 'Creating Zenya account'
                
                $body = ($account | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri     = "$baseUrl/scim/users"
                    Headers = $headers
                    Method  = 'POST'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
                }

                $createdUser = Invoke-RestMethod @splatWebRequest -Verbose:$false
                $aRef = [PSCustomObject]@{
                    id       = $createdUser.id
                    userName = $createdUser.userName
                }
                break
            }
            'Update-Correlate' {
                Write-Verbose 'Updating and correlating Zenya account'
                if ([string]::IsNullOrEmpty($CurrentUser.id)) {
                    throw "The user account [$($CurrentUser.userName) exists in Outsystem, but does not have a unique identifier [id]"
                }

                switch ($updateAction) {
                    'Update' {
                        $bodyUpdate = [PSCustomObject]@{
                            id = $currentUser.id
                            operations = @()
                        }
                        foreach($property in $propertiesChanged){
                            # Additional mapping for email object
                            if($property.name -eq 'emailValues'){
                                $bodyUpdate.operations += @{
                                    # op = "replace"
                                    # path = 'emails[type eq "work"].value'
                                    # value = $email
        
                                    op = "replace"
                                    path = "emails[type eq `"$($property.Value.type)`"].value"
                                    value = $property.value.value
                                }
                            }
                            else{
                                $bodyUpdate.operations += @{
                                    op = "replace"
                                    path = $property.name
                                    value = $property.value
                                }
                            }
                        }
                        $body = $bodyUpdate | ConvertTo-Json -Depth 10
                        Write-Verbose "Updating Zenya account $($currentUser.userName) ($($currentUser.id))"
                        Write-Verbose "Body: $body"
                        $splatWebRequest = @{
                            Uri     = "$baseUrl/scim/users/$($currentUser.id)"
                            Headers = $headers
                            Method  = 'PATCH'
                            Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
                        }
                        $updatedUser = Invoke-RestMethod @splatWebRequest -Verbose:$false
                        $aRef = [PSCustomObject]@{
                            id       = $updatedUser.id
                            userName = $updatedUser.userName
                        }

                        $auditLogs.Add([PSCustomObject]@{
                                Action = "UpdateAccount"
                                Message = "Update account was successful"
                                IsError = $false
                            })
                        break
                    }
                    'NoChanges' {
                        $aRef = [PSCustomObject]@{
                            id       = $CurrentUser.id
                            userName = $CurrentUser.userName
                        }

                        Write-Verbose "No changes to Zenya account $($CurrentUser.userName) ($($CurrentUser.id))"
                        $auditLogs.Add([PSCustomObject]@{
                                Action = "UpdateAccount"
                                Message = "Update was successful (No Changes needed)"
                                IsError = $false
                            })
                        break
                    }
                }
                break
            }

            'Correlate' {
                Write-Verbose 'Correlating Zenya account'
                if ([string]::IsNullOrEmpty($CurrentUser.id)) {
                    throw "The user account [$($CurrentUser.userName) exists in Outsystem, but does not have a unique identifier [id]"
                }

                $aRef = [PSCustomObject]@{
                    id       = $CurrentUser.id
                    userName = $CurrentUser.userName
                }
                break
            }
        }
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "CreateAccount"
                Message = "$action account was successful. userName is: [$($account.userName)]. AccountReference is: [$aRef]"
                IsError = $false
            })
    }
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

        $errorMessage = "Could not $action enya account $($account.username). Error: $($errorMessageDetail)"
    }
    else {
        $errorMessage = "Could not $action enya account $($account.username). Error: $($ex.Exception.Message)"
    }

    $verboseErrorMessage = "Could not $action Zenya account $($account.username). Error at Line '$($_.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error message: $($ex)"
    Write-Verbose $verboseErrorMessage
  
    $auditLogs.Add([PSCustomObject]@{
            Action = "CreateAccount"
            Message = $errorMessage
            IsError = $true
        })
}
finally {
    $result = [PSCustomObject]@{
        Success          = $success
        AccountReference = $aRef
        Auditlogs        = $auditLogs
        Account          = $account
 
        # Optionally return data for use in other systems
        ExportData       = [PSCustomObject]@{
            id          = $aRef.id
            userName    = $aRef.userName
        }; 
    }

    Write-Output $result | ConvertTo-Json -Depth 10
}