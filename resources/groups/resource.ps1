#####################################################
# HelloID-Conn-Prov-Target-Zenya-Resources-Groups
# Creates groups dynamically based on HR data
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
#endregion functions
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
try {
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
    #endregion Create headers

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

    #region Process resources
    # Ensure the resourceContext data is unique based on ExternalId and DisplayName
    # and always sorted in the same order (by ExternalId and DisplayName)
    $resourceData = $resourceContext.SourceData |
    Select-Object -Property ExternalId, DisplayName -Unique | # Ensure uniqueness
    Sort-Object -Property @{Expression = { $_.ExternalId } }, DisplayName # Ensure consistent order by sorting ExternalId as integer and then by DisplayName

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $correlationField = "external_id"
    $groupsGrouped = $groups | Group-Object -Property $correlationField -AsHashTable -AsString

    foreach ($resource in $resourceData) {
        #region get group for resource
        $actionMessage = "querying group for resource: $($resource | ConvertTo-Json)" 
       
        $correlationValue = "department_$($resource.ExternalId)"

        $correlatedResource = $null
        $correlatedResource = $groupsGrouped["$($correlationValue)"]
        #endregion get group for resource
        
        #region Calulate action
        if (($correlatedResource | Measure-Object).count -eq 0) {
            $actionResource = "CreateResource"
        }
        elseif (($correlatedResource | Measure-Object).count -eq 1) {
            $actionResource = "CorrelateResource"
        }
        #endregion Calulate action

        #region Process
        switch ($actionResource) {
            "CreateResource" {
                #region Create group
                # API docs: https://swagger.zenya-dev.nl/api/swagger/index.html#/UserGroups/PostUserGroup
                $actionMessage = "creating group for resource: $($resource | ConvertTo-Json)"

                # Create account body and set with default properties
                #
                if ([string]::IsNullOrEmpty($resource.Description)) {
                    $Description = $resource.DisplayName
                }
                else{
                    $Description = $resource.Description
                }
                $createGroupBody = [PSCustomObject]@{
                    external_id  = "department_$($resource.ExternalId)"
                    name = "$($resource.DisplayName)"
                    description = "$($Description)"
                }

                $createGroupSplatParams = @{
                    Uri         = "$($actionContext.Configuration.ApiBaseUrl)/api/user_groups"
                    Method      = "POST"
                    Body        = ($createGroupBody | ConvertTo-Json -Depth 10)
                    ContentType = 'application/json; charset=utf-8'
                    Verbose     = $false
                    ErrorAction = "Stop"
                }

                Write-Information "SplatParams: $($createGroupSplatParams | ConvertTo-Json)"

                if (-Not($actionContext.DryRun -eq $true)) {
                    # Add header after printing splat
                    $createGroupSplatParams['Headers'] = $headers

                     try {
                        $createGroupResponse = Invoke-RestMethod @createGroupSplatParams                   
                        $createdGroup = $createGroupResponse                        
                    }
                    catch {                      
                        if ($_.Exception.Response.StatusCode -eq 400) {
                             Write-Warning "The group  [$($createGroupBody.name)] and external_id [$($createGroupBody.external_Id)] could not be created in Zenya because it already exists, skipping creation."
                            $outputContext.AuditLogs.Add([PSCustomObject]@{                               
                                Message = "The group [$($createGroupBody.name)] and external_id [$($createGroupBody.external_Id)] could not be created in Zenya because it already exists, skipping creation."
                                IsError = $true
                            })                         
                          Continue
                        }
                        else {
                            throw
                        }
                    }
                    Write-Information "Created group with id [$($createdGroup.created_identifier)], Name [$($createGroupBody.name)] and externalId [$($createGroupBody.external_Id)]  for resource: $($resource | ConvertTo-Json)."                    
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created group with id [$($createdGroup.created_identifier)], Name [$($createGroupBody.name)] and externalId [$($createGroupBody.external_Id)]  for resource: $($resource | ConvertTo-Json)."
                            IsError = $false
                        })
                }   
                else {
                    Write-Warning "DryRun: Would create group with display_name [$($createGroupBody.name)] and external_id [$($createGroupBody.external_Id)]  for resource: $($resource | ConvertTo-Json)."
                }
                #endregion Create group
                break
            }            

            "CorrelateResource" {
                #region Correlate group
                $actionMessage = "correlating to group for resource: $($resource | ConvertTo-Json)"

                if (-Not($actionContext.DryRun -eq $true)) {
                    Write-Information "Correlated to group with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                }
                else {
                    Write-Warning "DryRun: Would correlate to group with id [$($correlatedResource.id)] on [$($correlationField)] = [$($correlationValue)]."
                }
                #endregion Correlate group

                break
            }
        }
        #endregion Process
    }
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
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}