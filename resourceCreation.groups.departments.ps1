#####################################################
# HelloID-Conn-Prov-Target-Zenya-ResourceCreation-Groups-Departments
#
# Version: 1.1.2
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json

# The resourceData used in this default script uses resources based on Title
$rRef = $resourceContext | ConvertFrom-Json
$success = $true # Set to true at start, because only when an error occurs it is set to false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

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
# $dryRun = $false

# Name format: Department-<department code>
$groupNamePrefix = "Department-"
$groupNameSuffix = ""

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
#endregion functions

# In preview only the first 10 items of the SourceData are used
foreach ($resource in $rRef.SourceData) {
    # Write-Information "Checking $($resource)"
    try {
        $groupName = ("$groupNamePrefix" + "$($resource.ExternalId)" + "$groupNameSuffix")

        $group = [PSCustomObject]@{
            schemas      = "urn:ietf:params:scim:schemas:core:2.0:Group"
            display_name = $groupName
        }

        $headers = New-AuthorizationHeaders -ClientId $clientId -ClientSecret $clientSecret

        Write-Verbose "Group lookup based on display name [$($group.display_name)]"
        $splatWebRequest = @{
            Uri     = "$baseUrl/scim/groups?filter=displayName%20eq%20%22$($group.display_name)%22"
            Headers = $headers
            Method  = 'GET'
        }

        $currentGroup = (Invoke-RestMethod @splatWebRequest -Verbose:$false).resources

        if ($currentGroup.Id.count -ge 1) {
            $groupExists = $true
        }
        else {
            $groupExists = $false
        }

        # If resource does not exist
        if ($groupExists -eq $False) {
            <# Resource creation preview uses a timeout of 30 seconds
            while actual run has timeout of 10 minutes #>
            Write-Verbose "Creating Zenya group with displayname $($group.display_name)"

            if (-Not($dryRun -eq $True)) {
                $body = ($group | ConvertTo-Json -Depth 10)
                $splatWebRequest = @{
                    Uri     = "$baseUrl/scim/groups"
                    Headers = $headers
                    Method  = 'POST'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body)) 
                }

                $createdGroup = Invoke-RestMethod @splatWebRequest -Verbose:$false

                $auditLogs.Add([PSCustomObject]@{
                        Message = "Successfully created group $($createdGroup.displayName) ($($createdGroup.Id))"
                        Action  = "CreateResource"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would create Zenya group with displayname $($group.display_name)"
            }
        }
        else {
            Write-Verbose "Skipping creating Zenya group with displayname $($group.display_name) already exists"

            if (-Not($dryRun -eq $True)) {
                $success = $True
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Skipped creating group Zenya group with displayname $($group.display_name) (already exists)"
                        Action  = "CreateResource"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would skip creating Zenya group with displayname $($group.display_name)  (already exists)"
            }
        }
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex
    
            $verboseErrorMessage = $errorObject.ErrorMessage
    
            $auditErrorMessage = Resolve-ZenyaErrorMessage -ErrorObject $errorObject.ErrorMessage
        }
    
        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }
    
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "CreateResource"
                Message = "Error creating Zenya group with displayname $($group.display_name). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10