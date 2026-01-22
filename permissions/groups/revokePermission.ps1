#####################################################
# HelloID-Conn-Prov-Target-Zenya-Permissions-Revoke
# Revoke groupmembership from account
# PowerShell V2
#####################################################



# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
    
    if ([string]::IsNullOrEmpty($($actionContext.References.Account.id))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference  
    $splatScimToken = @{
        ClientId     = $actionContext.Configuration.ScimClientId
        ClientSecret = $actionContext.Configuration.scimclientSecret
        TokenUri     = "$($ActionContext.Configuration.ScimBaseUrl)/oauth/token"  
    }    
    $scimToken = Get-AuthToken @splatScimToken

    $splatApiToken = @{       
        clientId     = $actionContext.Configuration.ApiClientId
        clientSecret = $actionContext.Configuration.ApiClientSecret
        TokenUri      = "$($ActionContext.Configuration.ApiBaseUrl)/api/oauth/token"  
    }
    $apiToken = Get-AuthToken @splatApiToken

    #endregion Create access token   

    #region Create headers
    $ScimHeaders = @{        
        "Content-Type" = "application/json;charset=utf-8"        
    }   
    $scimHeaders['Authorization'] = "$($scimToken.token_type) $($scimToken.access_token)"  
    
    $apiHeaders = @{
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
        "X-Api-Version" = 5
    }   
    $apiHeaders['Authorization'] = "$($apiToken.token_type) $($apiToken.access_token)"  
    #endregion Create headers

    
    Write-Information 'Verifying if a Zenya account exists'
    $splatGetUser = @{
        Uri     = "$($actionContext.Configuration.ScimBaseUrl)/scim/Users/$($actionContext.References.Account.id)"
        Method  = 'GET'
        Headers = $scimheaders
    }
    $correlatedAccount = Invoke-RestMethod @splatGetUser

    if ($null -ne $correlatedAccount) {
        $action = 'RevokePermission'
    }
    else {
        $action = 'NotFound'
    }

    switch ($action) {
        'RevokePermission' {                     
                    
            $revokePermissionBody = @{
                "remove_user_ids" = @($($actionContext.References.Account.Id))
            }

            $splatRevokeGroupMember = @{
                Uri = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups/$($actionContext.References.Permission.Id)"
                Method   = "PATCH"
                Body = ($revokePermissionBody | ConvertTo-Json -Depth 10)                   
                Headers = $apiHeaders
            }

            if (-not($actionContext.DryRun -eq $true)) {
                try {                   
               
                    Write-Information "Revoking Zenya permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Id)]"
                    $null = Invoke-RestMethod @splatRevokeGroupMember        
                 }
                catch {
                    if ($_.Exception.Response.StatusCode -eq 404) {
                        Write-Warning "The Zenya permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Id)] could not be found, skipping revocation."
                        $outputContext.AuditLogs.Add([PSCustomObject]@{
                                Action  = "RevokePermission"
                                Message = "The Zenya permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Id)] could not be found, skipping revocation."
                                IsError = $false
                            }) 
                      }                                              
                   else {
                        throw $PSItem
                    }
                }
            }
            else {
                Write-Information "[DryRun] Revoke Zenya permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Id)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Revoke permission [$($actionContext.PermissionDisplayName)] was successful"
                    IsError = $false
                })
        }
        'NotFound' {
            Write-Information "Zenya account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Zenya account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-ZenyaError -ErrorObject $ex
        $auditLogMessage = "Could not revoke Generic-Scim permission. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditLogMessage = "Could not revoke Generic-Scim permission. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditLogMessage
            IsError = $true
        })
}








    