#####################################################
# HelloID-Conn-Prov-Target-Zenya-SubPermissions-Groups-All
# Grants/revokes All groups
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

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

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

try {
    #region Verify account reference
    $actionMessage = "verifying account reference"
    
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference

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

    #region Get Groups
    # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetGroupsRequest
    $actionMessage = "querying Groups"

    $groups = [System.Collections.ArrayList]@()
    $skip = 0
    $take = 100
    do {
        $getGroupsSplatParams = @{
            Uri         = "$($actionContext.Configuration.serviceAddress)/scim/groups?startIndex=$($skip)&count=$($take)"
            Method      = "GET"
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }

        Write-Verbose "SplatParams: $($getGroupsSplatParams | ConvertTo-Json)"

        # Add header after printing splat
        $getGroupsSplatParams['Headers'] = $headers
    
        $getGroupsResponse = Invoke-RestMethod @getGroupsSplatParams

        if ($getGroupsResponse.Resources -is [array]) {
            [void]$groups.AddRange($getGroupsResponse.Resources)
        }
        else {
            [void]$groups.Add($getGroupsResponse.Resources)
        }

        $skip += $take
    } while (($groups | Measure-Object).Count -lt $getGroupsResponse.totalResults)

    Write-Information "Queried Groups. Result count: $(($groups | Measure-Object).Count)"
    #endregion Get Groups

    #region Define desired permissions
    $actionMessage = "calculating desired permission"

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $groupsGrouped = $groups | Group-Object -Property externalId -AsHashTable -AsString

    $desiredPermissions = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {
            $actionMessage = "calulating group for resource: $($resource | ConvertTo-Json)"

            Write-Verbose "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                # Get group to use objectGuid to avoid name change issues
                $correlationField = "externalId"

                # Example: department_<department externalId>
                $correlationValue = "department_" + $contract.Department.ExternalId

                $group = $null
                $group = $groupsGrouped["$($correlationValue)"]

                if (($group | Measure-Object).count -eq 0) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "No Group found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif (($group | Measure-Object).count -gt 1) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Multiple Groups found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the groups are unique."
                            IsError = $true
                        })
                }
                else {
                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.Id)"] = $group.DisplayName
                }
            }
        }
    }
    #endregion Define desired permissions

    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Warning ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))

    #region Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No permissions defined") {
            #region Revoke permission
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchGroup
            $actionMessage = "revoking group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create permission body
            $revokePermissionBody = [PSCustomObject]@{
                schemas    = @("urn:ietf:params:scim:schemas:core:2.0:Group")
                id         = $actionContext.References.Permission.id
                operations = @(
                    @{
                        op    = "remove"
                        path  = "members"
                        value = @(
                            @{
                                value   = $actionContext.References.Account.Id
                                display = $actionContext.References.Account.UserName
                            }
                        )
                    }
                )
            }
    
            $revokePermissionSplatParams = @{
                Uri         = "$($actionContext.Configuration.serviceAddress)/scim/groups/$($actionContext.References.Permission.Id)"
                Method      = "PATCH"
                Body        = ($revokePermissionBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Verbose "SplatParams: $($revokePermissionSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $revokePermissionSplatParams['Headers'] = $headers

                $revokePermissionResponse = Invoke-RestMethod @revokePermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoked group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would revoke group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Revoke permission
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }
    #endregion Compare current with desired permissions and revoke permissions

    #region Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            #region Grant permission
            # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchGroup
            $actionMessage = "granting group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create permission body
            $grantPermissionBody = [PSCustomObject]@{
                schemas    = @("urn:ietf:params:scim:schemas:core:2.0:Group")
                id         = $actionContext.References.Permission.id
                operations = @(
                    @{
                        op    = "add"
                        path  = "members"
                        value = @(
                            @{
                                value   = $actionContext.References.Account.Id
                                display = $actionContext.References.Account.UserName
                            }
                        )
                    }
                )
            }
    
            $grantPermissionSplatParams = @{
                Uri         = "$($actionContext.Configuration.serviceAddress)/scim/groups/$($actionContext.References.Permission.Id)"
                Method      = "PATCH"
                Body        = ($grantPermissionBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Verbose "SplatParams: $($grantPermissionSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $grantPermissionSplatParams['Headers'] = $headers

                $grantPermissionResponse = Invoke-RestMethod @grantPermissionSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Granted group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would grant group [$($actionContext.References.Permission.Name)] with id [$($actionContext.References.Permission.id)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Grant permission
        }    
    }
    #endregion Compare desired with current permissions and grant permissions
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
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($actionContext.Operation -match "update|grant" -AND $outputContext.SubPermissions.count -eq 0) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "No permissions defined"
                Reference   = [PSCustomObject]@{ Id = "No permissions defined" }
            })

        Write-Warning "Skipped granting permissions for account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No permissions defined."
    }

    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}