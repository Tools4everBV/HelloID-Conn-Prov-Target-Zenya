#####################################################
# HelloID-Conn-Prov-Target-Zenya-DynamicPermissions
#
# Version: 1.0.0
#####################################################
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json
# The entitlementContext contains the sub permissions (Previously the $permissionReference variable)
$eRef = $entitlementContext | ConvertFrom-Json
# Determine the current permissions
$currentPermissions = @{}
foreach ($permission in $eRef.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}
# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$subPermissions = [System.Collections.Generic.List[PSCustomObject]]::new()
$success = $false # Set to false at start, at the end, only when no error occurs it is set to true
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Zenya Scim endpoints
$baseUrl = $c.serviceAddress
$clientId = $c.clientId
$clientSecret = $c.clientSecret

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

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
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
        
        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
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

        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Error creating authorization headers. Error Message: $($errorMessage.AuditErrorMessage)"
                IsError = $true
            })

        # Skip further actions, as this is a critical error
        continue
    }

    #region Change mapping here
    $desiredPermissions = @{}
    if ($o -ne "revoke") {
        # Example: Contract Based Logic:
        foreach ($contract in $p.Contracts) {
            Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
            if ($contract.Context.InConditions -OR ($dryRun -eq $True)) {
                try {
                    # Example: department_<departmentname>
                    $groupName = "department-" + $contract.Department.ExternalId

                    # Get group to use id to avoid name change issues
                    $filter = "displayName eq `"$($groupName)`""
                    Write-Verbose "Querying group that matches filter [$($filter)]"

                    $splatWebRequest = @{
                        Uri             = "$baseUrl/scim/groups?filter=$([System.Uri]::EscapeDataString($filter))"
                        Headers         = $headers
                        Method          = 'GET'
                        ContentType     = "application/json;charset=utf-8"
                        UseBasicParsing = $true
                    }
                    $group = $null
                    $group = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

                    if (($group | Measure-Object).count -eq 0) {
                        $auditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "No Group found that matches filter [$($filter)]"
                                IsError = $true
                            })
                        continue
                    }
                    elseif (($group | Measure-Object).count -gt 1) {
                        $auditLogs.Add([PSCustomObject]@{
                                # Action  = "" # Optional
                                Message = "Multiple Groups found that matches filter [$($filter)]. Please correct this so the groups are unique."
                                IsError = $true
                            })
                        continue
                    }

                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.Id)"] = $group.DisplayName
                }
                catch {
                    $ex = $PSItem
                    $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                    Write-Error "URI: $($splatWebRequest.Uri)"

                    $auditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Error calculation dynamic permissions. Error Message: $($errorMessage.AuditErrorMessage)"
                            IsError = $true
                        })
                }
            }
        }
    }
    #endregion Change mapping here

    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

    Write-Warning ("Existing Permissions: {0}" -f ($eRef.CurrentPermissions.DisplayName | ConvertTo-Json))

    #region Execute
    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })
        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            # Grant permission for account
            try {
                # Create custom add permission object
                $grantPermissionObject = [PSCustomObject]@{
                    schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
                    id         = $permission.Name
                    operations = @(
                        @{
                            op    = "add"
                            path  = "members"
                            value = @(
                                @{
                                    value   = $aRef.id
                                    display = $aRef.userName
                                }
                            )
                        }
                    )
                }
                $body = ($grantPermissionObject | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri             = "$baseUrl/scim/groups/$($permission.Name)"
                    Headers         = $headers
                    Method          = 'PATCH'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                if (-not($dryRun -eq $true)) {
                    Write-Verbose "Granting permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"

                    $grantedPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $auditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Successfully granted permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would grant permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
                
                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                Write-Error "URI: $($splatWebRequest.Uri)"
                Write-Error "Body: $([System.Text.Encoding]::UTF8.GetString($splatWebRequest.Body))"

                $auditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Error granting permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $true
                    })
            }
        }
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) { 
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined") {
            # Revoke permission for account
            try {
                # Create custom add permission object
                $revokePermissionObject = [PSCustomObject]@{
                    schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
                    id         = $permission.Name
                    operations = @(
                        @{
                            op    = "remove"
                            path  = "members"
                            value = @(
                                @{
                                    value   = $aRef.id
                                    display = $aRef.userName
                                }
                            )
                        }
                    )
                }
                $body = ($revokePermissionObject | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri             = "$baseUrl/scim/groups/$($permission.Name)"
                    Headers         = $headers
                    Method          = 'PATCH'
                    Body            = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    ContentType     = "application/json;charset=utf-8"
                    UseBasicParsing = $true
                }

                if (-not($dryRun -eq $true)) {
                    Write-Verbose "Revoking permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"

                    $revokedPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $auditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Successfully revoked permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would revoke permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]"
                }
            }
            catch {
                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
                Write-Error "URI: $($splatWebRequest.Uri)"
                Write-Error "Body: $([System.Text.Encoding]::UTF8.GetString($splatWebRequest.Body))"

                $auditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Error revoking permission to group [$($permission.Value) ($($permission.Name))] for account [$($aRef.userName) ($($aRef.id))]. Error Message: $($errorMessage.AuditErrorMessage)"
                        IsError = $true
                    })
            }
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }

    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($o -match "update|grant" -AND $subPermissions.count -eq 0) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($auditLogs.IsError -contains $true)) {
        $success = $true
    }

    # Send results
    $result = [PSCustomObject]@{
        Success        = $success
        SubPermissions = $subPermissions
        AuditLogs      = $auditLogs
    }

    Write-Output ($result | ConvertTo-Json -Depth 10)
}