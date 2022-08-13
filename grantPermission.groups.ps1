#####################################################
# HelloID-Conn-Prov-Target-Zenya-GrantPermission-Group
#
# Version: 1.1.1
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json

# The permissionReference object contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json
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

# Troubleshooting
# $aRef = @{
#     userName = "TestHelloID@enyoi.onmicrosoft.com"
#     id       = "64e1c737-0274-4ba6-ae12-201edbe77d99"
# }
# $dryRun = $false

#region Functions
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
#endregion Functions

# Get current Zenya account
try {
    if ($null -eq $aRef.id) {
        throw "No Account Reference found in HelloID"
    }

    $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

    Write-Verbose "Querying Zenya account with id $($aRef.id)"
    $splatWebRequest = @{
        Uri     = "$baseUrl/scim/users/$($aRef.id)"
        Headers = $headers
        Method  = 'GET'
    }
    $currentUser = $null
    $currentUser = Invoke-RestMethod @splatWebRequest -Verbose:$false

    if ($null -eq $currentUser.id) {
        throw "No User found in Zenya with id $($aRef.id)"
    }
}
catch {
    $ex = $PSItem
    $verboseErrorMessage = $ex
    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $ex
    if ($auditErrorMessage -Like "No User found in Zenya with id $($aRef.id)" -or $auditErrorMessage -Like "*(404) Not Found.*") {
        if (-Not($dryRun -eq $True)) {
            $success = $false
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "No Zenya account found with id $($aRef.id). Possibly deleted."
                    IsError = $false
                })
        }
        else {
            Write-Warning "DryRun: No Zenya account found with id $($aRef.id). Possibly deleted."
        }        
    }
    else {
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Error querying Zenya account with id $($aRef.id). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

# Grant permission Zenya group for Zenya account
if ($null -ne $currentUser.id) {
    try {
        Write-Verbose "Granting permission to $($pRef.Name) ($($pRef.id)) for $($currentUser.userName) ($($currentUser.id))"

        $bodyGroupAddMember = [PSCustomObject]@{
            schemas    = "urn:ietf:params:scim:schemas:core:2.0:Group"
            id         = $pRef.id
            operations = @(
                @{
                    op    = "add"
                    path  = "members"
                    value = @(
                        @{
                            value   = $currentUser.id
                            display = $currentUser.userName
                        }
                    )
                }
            )
        }
        $body = ($bodyGroupAddMember | ConvertTo-Json -Depth 10)

        $splatWebRequest = @{
            Uri     = "$baseUrl/scim/groups/$($pRef.id)"
            Headers = $headers
            Method  = 'PATCH'
            Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
        }
        if (-not($dryRun -eq $true)) {
            $addGroupMember = Invoke-RestMethod @splatWebRequest -Verbose:$false
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission"
                    Message = "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($currentUser.userName) ($($currentUser.id))"
                    IsError = $false
                })
        }
        else {
            Write-Warning "DryRun: Would grant permission to $($pRef.Name) ($($pRef.id)) for $($currentUser.userName) ($($currentUser.id))"
        }
    }
    catch {
        $ex = $PSItem
        $verboseErrorMessage = $ex
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        
        $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $ex
        
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Error granting permission to Group $($pRef.Name) ($($pRef.id)) for $($currentUser.userName) ($($currentUser.id)). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

# Send results
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    AuditLogs        = $auditLogs
    Account          = $account
}
Write-Output $result | ConvertTo-Json -Depth 10