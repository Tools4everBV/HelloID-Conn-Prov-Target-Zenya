#####################################################
# HelloID-Conn-Prov-Target-Zenya-DynamicPermissions
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

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{ }
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

# Define correlation property of groups - This has to be unique
$correlationProperty = "externalId"

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

        # Group on correlation property to check if group exists (as correlation property has to be unique for a group)
        $groupsGrouped = $groups | Group-Object $correlationProperty -AsHashTable -AsString

        Write-Information "Successfully queried groups. Result count: $(($groups | Measure-Object).Count)"
    }
    catch {
        $ex = $PSItem
        $errorMessage = Get-ErrorMessage -ErrorObject $ex

        Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
        Write-Verbose "URI: $($splatWebRequest.Uri)"

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error querying groups. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Throw terminal error
        throw
    }

    $desiredPermissions = @{ }
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {
            Write-Verbose "Contract in condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $True)) {
                try {
                    # Example: department_<department externalId>
                    $correlationValue = "department_" + $contract.Department.ExternalId

                    # Get group to use id to avoid name change issues
                    $filter = "$correlationProperty -eq `"$($correlationValue)`""
                    Write-Verbose "Querying group that matches filter [$($filter)]"

                    $group = $null
                    $group = $groupsGrouped["$($correlationValue)"]

                    if (($group | Measure-Object).count -eq 0) {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "No Group found that matches filter [$($filter)]"
                                IsError = $true
                            })
                    }
                    elseif (($group | Measure-Object).count -gt 1) {
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Multiple Groups found that matches filter [$($filter)]. Please correct this so the groups are unique."
                                IsError = $true
                            })
                    }
                    else {
                        # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                        $desiredPermissions["$($group.Id)"] = $group.DisplayName
                    }
                }
                catch {
                    $ex = $PSItem
                    $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                    Write-Verbose "URI: $($splatWebRequest.Uri)"
            
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Error calculation dynamic permissions. Error Message: $($errorMessage.AuditErrorMessage)"
                            IsError = $true
                        })
            
                    # Throw terminal error
                    throw
                }
            }
        }
    }
    Write-Warning ("Existing Permissions: {0}" -f ($eRef.CurrentPermissions.DisplayName | ConvertTo-Json))
    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

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

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error querying account with id [$($actionContext.References.Account.Id)]. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Throw terminal error
        throw
    }

    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            # Grant permission
            try {
                Write-Verbose "Granting permission to $($permission.Value) ($($permission.Name)) for $($currentAccount.userName) ($($currentAccount.id))"

                # Create permission body
                $permissionBody = [PSCustomObject]@{
                    schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
                    id         = $permission.Name
                    operations = @(
                        @{
                            op    = "add"
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
                    Uri             = "$baseUrl/scim/groups/$($permission.Name)"
                    Headers         = $headers
                    Method          = 'PATCH'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Granting permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"

                    $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Successfully granted permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would grant permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
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
                        Message = "Error granting permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $true
                    })

                # Throw terminal error
                throw
            }
        }
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{ }
    foreach ($permission in $currentPermissions.GetEnumerator()) {
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined") {
            # Revoke permission
            try {
                Write-Verbose "Revoking permission to $($permission.Value) ($($permission.Name)) for $($currentAccount.userName) ($($currentAccount.id))"

                # Create permission body
                $permissionBody = [PSCustomObject]@{
                    schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
                    id         = $permission.Name
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
                    Uri             = "$baseUrl/scim/groups/$($permission.Name)"
                    Headers         = $headers
                    Method          = 'PATCH'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Verbose "Revoking permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"

                    $revokePermission = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Successfully revoked permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would revoke permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]"
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
                        Message = "Error revoking permission: [$($permission.Value) ($($permission.Name))] to account: [$($currentAccount.userName) ($($currentAccount.id))]. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $true
                    })

                # Throw terminal error
                throw
            }
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }
}
catch {
    $ex = $PSItem
    Write-Warning "Terminal error occurred. Error Message: $($ex.Exception.Message)"
}
finally {
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}