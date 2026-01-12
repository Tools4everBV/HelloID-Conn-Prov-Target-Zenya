#####################################################
# HelloID-Conn-Prov-Target-Zenya-SubPermissions-Groups-All
# Grants/revokes All groups 
#####################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
function Get-AuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ClientId,

        [Parameter(Mandatory)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory)]
        [string]
        $TokenUri
    )

    try {
        $headers = @{
            'content-type' = 'application/x-www-form-urlencoded'
        }

        $body = @{
            client_id     = $ClientID
            client_secret = $ClientSecret            
            grant_type    = 'client_credentials'
        }

        Invoke-RestMethod -Uri $TokenUri -Method 'POST' -Body $body -Headers $headers
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
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

    #region Create access token
   
    $actionMessage = "creating access token"    
    $splatApiToken = @{       
        clientId     = $actionContext.Configuration.ApiClientId
        clientSecret = $actionContext.Configuration.ApiClientSecret
        TokenUri     = "$($ActionContext.Configuration.ApiBaseUrl)/api/oauth/token"  
    }
    $apiToken = Get-AuthToken @splatApiToken
  
    #endregion Create access token
    #region Create headers
    $actionMessage = "creating headers"
    $headers = @{
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
        "X-Api-Version" = 5
    }   
    $headers['Authorization'] = "$($apiToken.token_type) $($apiToken.access_token)"          

    #region Get Groups
    # API docs:https://swagger.zenya-dev.nl/api/swagger/index.html#/UserGroups/GetUserGroups
    $actionMessage = "querying Groups"

    $groups = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $take = 100     
    do {
       
        $getGroupsSplatParams = @{
            Uri     = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups?offset=$($skip)&envelope=true&include_total=true&limit=$($take)"
            Method  = "GET"
            Headers = $headers            
        } 
        $getGroupsResponse = Invoke-RestMethod @getGroupsSplatParams
        $result = $getGroupsResponse.Data 
        foreach ($importedGroup in $result) {            
            if (($importedGroup.user_group_type -ne "synced") -and ($importedGroup.user_group_type -ne "system")) {                                      
                [void]$groups.Add($importedGroup)  
            } 
        }

        $skip += $getGroupsResponse.pagination.returned
    } while (($skip -lt $getGroupsResponse.pagination.total) -OR ($getGroupsResponse.pagination.returned -lt 1))    

    $groups = $groups | Sort-Object user_group_id -unique
    Write-Information "Queried Groups. Result count: $(($groups.count))"
    #endregion Get Groups

    #region Define desired permissions
    $actionMessage = "calculating desired permission"

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $groupsGrouped = $groups | Group-Object -Property external_id -AsHashTable -AsString

    $desiredPermissions = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {          
          
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {
                # Get group to use objectGuid to avoid name change issues
                $correlationField = "external_id"

                # Example: department_<department externalId>
                $correlationValue = "department_" + $contract.Department.ExternalId

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
                    $desiredPermissions["$($group.user_group_id)"] = $group.name
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
            # API docs:https://swagger.zenya-dev.nl/api/swagger/index.html#/UserGroups/PatchUserGroup
            $actionMessage = "revoking group [$($permission.value)] with id [$($permission.name)] from account with AccountReference: $($actionContext.References.Account.Id | ConvertTo-Json)"

            if ($null -eq $groups[$permission.name]) {
                Write-Warning "The group [$($permission.value)] with id [$($permission.name)] could not be found in Zenya, skipping revoke."
                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "The group [$($permission.value)] with id [$($permission.name)] could not be found in Zenya, skipping revoke."
                        IsError = $false
                    })  
                continue
            }

            $revokePermissionBody = @{
                "remove_user_ids" = @($($actionContext.References.Account.Id))
            }

            $splatRevokeGroupMember = @{
                Uri     = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups/$($permission.name)"
                Method  = "PATCH"
                Body    = ($revokePermissionBody | ConvertTo-Json -Depth 10)                   
                Headers = $Headers
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Revoking Zenya permission: [$($permission.value)] - [$($permission.name)]" 
                try{                
                $null = Invoke-RestMethod @splatRevokeGroupMember        
                }
                catch {
                    if ($_.Exception.Response.StatusCode -eq 404)
                    {
                        Write-Warning "The group [$($permission.value)] with id [$($permission.name)] could not be found in Zenya, skipping revoke."
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Action  = "RevokePermission"
                                Message = "The group [$($permission.value)] with id [$($permission.name)] could not be found in Zenya, skipping revoke."
                                IsError = $false
                            })  
                        continue
                    }
                    else {
                           throw $PSItem                       
                    }

                }
            }
            else {
                Write-Information "[DryRun] Revoke Zenya permission: [$($permission.value)] - [$($permission.name)] from account with AccountReference: $($actionContext.References.Account.id), will be executed during enforcement"
            }
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Revoked group [$($permission.value)] with id [$($permission.name)] from account with AccountReference: $($actionContext.References.Account.id)."
                    IsError = $false
                })  
                
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
            # API docs:https://swagger.zenya-dev.nl/api/swagger/index.html#/UserGroups/PatchUserGroup
            $actionMessage = "granting group [$($permission.value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account.id)"

            $grantPermissionBody = @{
                "add_user_ids" = @($($actionContext.References.Account.Id))
            }

            $splatGrantGroupMember = @{
                Uri     = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups/$($permission.Name)"
                Method  = "PATCH"
                Body    = ($grantPermissionBody | ConvertTo-Json -Depth 10)                   
                Headers = $Headers
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Granting Zenya permission: [$($permission.value)] - [$($permission.Name)]"
                $null = Invoke-RestMethod @splatGrantGroupMember        
            }
            else {
                Write-Information "[DryRun] Grant Zenya permission: [$($permission.value)] - [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account.id), will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Granted group [$($permission.value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account.id)."
                    IsError = $false
                  
            })           
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