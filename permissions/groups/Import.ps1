####################################################################
# HelloID-Conn-Prov-Target-Zenya-ImportPermissions-Group
# PowerShell V2
####################################################################

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
#endregion

try {
    #region Create access token   
   $splatApiToken = @{       
        clientId     = $actionContext.Configuration.ApiClientId
        clientSecret = $actionContext.Configuration.ApiClientSecret
        TokenUri      = "$($ActionContext.Configuration.ApiBaseUrl)/api/oauth/token"  
    }
    $apiToken = Get-AuthToken @splatApiToken
  
    #endregion Create access token

    $headers = @{
        "Accept"        = "application/json"
        "Content-Type"  = "application/json;charset=utf-8"
        "X-Api-Version" = 5
    }   
    $headers['Authorization'] = "$($apiToken.token_type) $($apiToken.access_token)"    

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

                # Make sure the displayName has a value
                if ([string]::IsNullOrEmpty($importedGroup.name))
                {                  
                     $displayName = "Group - $($importedGroup.user_group_id))"
                }
                else {
                    $displayName = "Group - $($importedGroup.name))"
                    $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))
                }                           

                $permission = @{
                    PermissionReference = @{
                        Reference = $importedGroup.user_group_id
                    }
                    Description         = "$($importedGroup.description)"
                    DisplayName         =  $displayName
                    AccountReferences   = $null
                }

                $GroupMembersSplatParams = @{
                    Uri     = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups/members?UserGroupIds=$($importedGroup.user_group_id)"
                    Method  = "GET" 
                    Headers = $headers            
                }

                $importedGroupMembers = Invoke-RestMethod @GroupMembersSplatParams
                     
                # The code below splits a list of permission-members into batches of <batchSize>
                # Each batch is assigned to $permission.AccountReferences and the permission object will be returned to HelloID for each batch
                # Ensure batching is based on the number of account references to prevent exceeding the maximum limit of 500 account references per batch
        
                $batchSize = 500
                for ($i = 0; $i -lt  $importedGroupMembers.Count; $i += $batchSize) {
                    $UserIdArray = [array] $importedGroupMembers[$i..([Math]::Min($i + $batchSize - 1, $importedGroupMembers.Count - 1))].user_id
                    $permission.AccountReferences = @() 
                    foreach ($userId in $UserIdArray) {                       
                        $permission.AccountReferences += @{
                            id = $userId
                        }
                    }
                    Write-Output $permission
                }
            }           
        }        
        $skip += $getGroupsResponse.pagination.returned
    } while (($skip -lt $getGroupsResponse.pagination.total) -OR ($getGroupsResponse.pagination.returned -lt 1))    
      
    
    Write-Information 'Zenya permission group entitlement import completed'

} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-ZenyaError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Generic-Scim permission group entitlements. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Generic-Scim permission group entitlements. Error: $($ex.Exception.Message)"
    }
}