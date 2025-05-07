#####################################################
# HelloID-Conn-Prov-Target-Zenya-Permissions-Groups-Import
# List groups as permissions
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

try {
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

    $actionMessage = "creating headers"
    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json;charset=utf-8"
    }
    Write-Information "Created headers. Result (without Authorization): $($headers | ConvertTo-Json)."
    # Add Authorization after printing splat
    $headers['Authorization'] = "$($createAccessTokenResonse.token_type) $($createAccessTokenResonse.access_token)"

    # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetGroupsRequest
    $actionMessage = "querying groups"
    $groups = [System.Collections.ArrayList]@()
    $skip = 1
    $take = 100
    do {
        $getGroupsSplatParams = @{
            Uri         = "$($actionContext.Configuration.serviceAddress)/scim/groups?startIndex=$($skip)&count=$($take)"
            Headers     = $headers
            Method      = "GET"
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }  
        $getGroupsResponse = Invoke-RestMethod @getGroupsSplatParams
        if ($getGroupsResponse.Resources -is [array]) {
            [void]$groups.AddRange($getGroupsResponse.Resources)
        }
        else {
            [void]$groups.Add($getGroupsResponse.Resources)
        }
        $skip += $take
    } while ($groups.Count -lt $getGroupsResponse.totalResults)
    Write-Information "Queried Groups. Result count: $($groups.Count)"

    # API docs: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUsersRequest
    $actionMessage = "querying users"
    $users = [System.Collections.ArrayList]@()
    $skip = 1
    $take = 100
    do {
        $getUsersSplatParams = @{
            Uri             = "$($actionContext.Configuration.serviceAddress)/scim/users?startIndex=$($skip)&count=$($take)"
            Headers         = $headers
            Method          = "GET"
            ContentType     = "application/json;charset=utf-8"
            UseBasicParsing = $true
            Verbose         = $false
            ErrorAction     = "Stop"
        }
        $getUsersResponse = Invoke-RestMethod @getUsersSplatParams
        if ($getUsersResponse.Resources -is [array]) {
            [void]$users.AddRange($getUsersResponse.Resources)
        }
        else {
            [void]$users.Add($getUsersResponse.Resources)
        }
        $skip += $take
    } while ($users.Count -lt $getUsersResponse.totalResults)
    Write-Information "Queried Users. Result count: $($users.Count)"
    $usersGrouped = $users | Group-Object -Property 'id' -AsHashTable -AsString

    foreach ($group in $groups) {
        $accounts = @()
        $memberships = $group.members
        foreach ($membership in $memberships) {
            $userName = $usersGrouped[$membership.value].userName
            if ($userName) {
                $account = @{
                    id       = $membership.value
                    userName = $userName
                }
                $accounts += $account
            }
        }
        $numberOfAccounts = $accounts.Count

        # Shorten DisplayName to max. 100 chars
        $displayName = "Group - $($group.DisplayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length))

        # Shorten Description to max. 100 chars
        $description = $($group.'urn:iprova:schemas:customproperties:Group'.description)
        if (-not([string]::IsNullOrEmpty($description))) {
            $description = $description.substring(0, [System.Math]::Min(100, $description.Length))
        }

        $permission = @{
            PermissionReference = @{
                Id = $group.id
            }       
            Description         = $description
            DisplayName         = $displayName
        }
        # Batch permissions based on the amount of account references, 
        # to make sure the output objects are not above the limit
        $accountsBatchSize = 500
        if ($numberOfAccounts -gt 0) {
            $batches = 0..($numberOfAccounts - 1) | Group-Object { [math]::Floor($_ / $accountsBatchSize ) }
            foreach ($batch in $batches) {
                $permission.AccountReferences = [array]($batch.Group | ForEach-Object { @($accounts[$_]) })
                Write-Output $permission
            }
        }
    }
    Write-Information 'Target permission import for groups is completed'
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

    # Required to write an error as the listing of permissions doesn't show auditlog
    Write-Error $auditMessage
}