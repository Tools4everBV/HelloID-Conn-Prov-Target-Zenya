#####################################################
# HelloID-Conn-Prov-Target-Zenya-Create
#
# Version: 1.1.1
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
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

# Set to true if accounts in the target system must be updated
$updateAccount = $true

# Account mapping
$account = [PSCustomObject]@{
    schemas           = "urn:ietf:params:scim:schemas:core:2.0:User"
    externalId        = $p.ExternalId
    userName          = $p.Accounts.MicrosoftActiveDirectory.UserPrincipalName
    displayname       = $p.Accounts.MicrosoftActiveDirectory.DisplayName
    preferredLanguage = "nl-NL"
    active            = $False
    emails            = [PSCustomObject]@{
        value   = $p.Accounts.MicrosoftActiveDirectory.mail
        type    = "work"
        primary = $True
    }
}

# Troubleshooting
$account = [PSCustomObject]@{
    schemas           = "urn:ietf:params:scim:schemas:core:2.0:User"
    externalId        = "99999999"
    userName          = "TestHelloID@enyoi.onmicrosoft.com2"
    displayname       = "Test HelloID"
    preferredLanguage = "nl-NL"
    active            = $False
    emails            = @(
        [PSCustomObject]@{
            value   = "TestHelloID2@enyoi.onmicrosoft.com"
            type    = "work"
            primary = $True
        }
    )
}
$dryRun = $false

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
                $errorObjectDetail = [regex]::Matches($errorObjectConverted.detail, '\{(.*?)\}').Value
                if ($null -ne $errorObjectDetail) {
                    try {
                        $errorDetailConverted = $errorObjectDetail | ConvertFrom-Json -ErrorAction Stop

                        if ($null -ne $errorDetailConverted) {
                            $errorMessage = $errorDetailConverted.title
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
            $errorMessage = "$($ErrorObject.Exception.Message)"
        }

        Write-Output $errorMessage
    }
}
#endregion functions

# Begin
# Get current Zenya account and verify if a user must be either [created], [updated and correlated] or just [correlated]
try {
    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose "Querying Zenya account with userName $($account.userName)"
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/users?filter=userName%20eq%20%22$($account.userName)%22"
        Headers = $headers
        Method  = 'GET'
    }
    $currentUser = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources


    if ($null -ne $currentUser.id) {
        Write-Verbose "Successfully queried Zenya account with userName $($account.userName):  $($currentUser.id)"
        
        if ($updateAccount -eq $true) {
            $action = 'Update-Correlate'

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
        else {
            $action = 'Correlate'
        }
    } 
    else {
        Write-Verbose "Could not query Zenya account with userName $($account.userName). Creating new acount"
        $action = 'Create'
    }
}
catch {
    $ex = $PSItem
    $verboseErrorMessage = $ex
    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $ex

    $success = $false  
    $auditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Error querying Zenya account with userName $($account.userName). Error Message: $auditErrorMessage"
            IsError = $True
        })
}

# Add an auditMessage showing what will happen during enforcement
if ($dryRun -eq $true) {
    $auditLogs.Add([PSCustomObject]@{
            Message = "$action Zenya account [$($account.userName)], will be executed during enforcement"
        })
}

# Process
# Get current Zenya account and verify if a user must be either [created], [updated and correlated] or just [correlated]
switch ($action) {
    'Create' {
        try {
            Write-Verbose "Creating Zenya account with userName $($account.userName)"
                
            $body = ($account | ConvertTo-Json -Depth 10)
            $splatWebRequest = @{
                Uri     = "$baseUrl/scim/users"
                Headers = $headers
                Method  = 'POST'
                Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
            }

            if (-not($dryRun -eq $true)) {
                $createdUser = Invoke-RestMethod @splatWebRequest -Verbose:$false
                $aRef = [PSCustomObject]@{
                    id       = $createdUser.id
                    userName = $createdUser.userName
                }

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "CreateAccount"
                        Message = "Successfully created Zenya account $($aRef.userName) ($($aRef.id))"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would create Zenya account with userName $($account.userName)"
            }
            break
        }
        catch {
            $ex = $PSItem
            $verboseErrorMessage = $ex
            Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        
            $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $ex
        
            $success = $false  
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "CreateAccount"
                    Message = "Error creating Zenya account with userName $($account.userName). Error Message: $auditErrorMessage"
                    IsError = $True
                })
        }
    }
    'Update-Correlate' {
        Write-Verbose "Updating and correlating Zenya account $($currentUser.userName) ($($currentUser.id))"
        if ([string]::IsNullOrEmpty($currentUser.id)) {
            throw "The user account [$($currentUser.userName) exists in Zenya, but does not have a unique identifier [id]"
        }

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
                                Action  = "CreateAccount"
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
                    $verboseErrorMessage = $ex
                    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                    
                    $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $ex
                    
                    $success = $false  
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "CreateAccount"
                            Message = "Error updating Zenya account $($currentUser.userName) ($($currentUser.id)). Error Message: $auditErrorMessage"
                            IsError = $True
                        })
                }
            }
            'NoChanges' {
                Write-Verbose "No changes to Zenya account $($currentUser.userName) ($($currentUser.id))"

                $aRef = [PSCustomObject]@{
                    id       = $currentUser.id
                    userName = $currentUser.userName
                }

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "CreateAccount"
                        Message = "Successfully updated Zenya account $($aRef.userName) ($($aRef.id)) (No Changes needed)"
                        IsError = $false
                    })
                break
            }
        }
        break
    }
    'Correlate' {
        Write-Verbose "Correlating Zenya account $($currentUser.userName) ($($currentUser.id))"
        if ([string]::IsNullOrEmpty($currentUser.id)) {
            throw "The user account [$($currentUser.userName) exists in Zenya, but does not have a unique identifier [id]"
        }

        $aRef = [PSCustomObject]@{
            id       = $currentUser.id
            userName = $currentUser.userName
        }
        break
    }
}

# finally {
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    Auditlogs        = $auditLogs
    Account          = $account
 
    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{
        id       = $aRef.id
        userName = $aRef.userName
    }; 
}

Write-Output $result | ConvertTo-Json -Depth 10