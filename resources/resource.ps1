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

    Write-Information "Created access token. Expires in: $($createAccessTokenResonse.expires_in | ConvertTo-Json)"
    #endregion Create access token

    #region Create headers
    $actionMessage = "creating headers"

    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json;charset=utf-8"
    }

    Write-Information "Created headers. Result (without Authorization): $($headers | ConvertTo-Json)."

    # Add Authorization after printing splat
    $headers['Authorization'] = "$($createAccessTokenResonse.token_type) $($createAccessTokenResonse.access_token)"
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

        Write-Information "SplatParams: $($getGroupsSplatParams | ConvertTo-Json)"

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

    #region Process resources
    # Ensure the resourceContext data is unique based on ExternalId and DisplayName
    # and always sorted in the same order (by ExternalId and DisplayName)
    $resourceData = $resourceContext.SourceData |
    Select-Object -Property ExternalId, DisplayName -Unique | # Ensure uniqueness
    Sort-Object -Property @{Expression = { [int]$_.ExternalId } }, DisplayName # Ensure consistent order by sorting ExternalId as integer and then by DisplayName

    # Group on ExternalId to check if group exists (as correlation property has to be unique for a group)
    $groupsGrouped = $groups | Group-Object -Property externalId -AsHashTable -AsString

    foreach ($resource in $resourceData) {
        #region get group for resource
        $actionMessage = "querying group for resource: $($resource | ConvertTo-Json)"
 
        $correlationField = "externalId"
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
                # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PostGroupRequest
                $actionMessage = "creating group for resource: $($resource | ConvertTo-Json)"

                # Create account body and set with default properties
                $createGroupBody = [PSCustomObject]@{
                    schemas      = "urn:ietf:params:scim:schemas:core:2.0:Group"
                    external_id  = "department_$($resource.ExternalId)"
                    display_name = "$($resource.DisplayName)"
                }

                $createGroupSplatParams = @{
                    Uri         = "$($actionContext.Configuration.serviceAddress)/scim/groups"
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

                    $createGroupResponse = Invoke-RestMethod @createGroupSplatParams
                    $createdGroup = $createGroupResponse

                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            # Action  = "" # Optional
                            Message = "Created group with id [$($createdGroup.id)], displayName [$($createdGroup.displayName)] and externalId [$($createdGroup.externalId)]  for resource: $($resource | ConvertTo-Json)."
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would create group with display_name [$($createGroupBody.display_name)] and external_id [$($createGroupBody.external_id)]  for resource: $($resource | ConvertTo-Json)."
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