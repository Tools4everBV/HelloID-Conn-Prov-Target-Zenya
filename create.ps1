$config = ConvertFrom-Json $configuration;

#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$auditMessage = " not created succesfully";

#iProva system data
$url = $config.url
$grant_type = 'client_credentials'
$client_id = $config.clientid
$client_secret = $config.clientsecret

#Create calculated attributes
$displayname = $p.Name.NickName + " " + $p.Custom.SurnameCombined
$email = $p.Accounts.GoogleGSuite.userName
$username = $p.ExternalId

#mapping
$account = @{
    schemas = "urn:ietf:params:scim:schemas:core:2.0:User"
    externalId = $p.ExternalId
    userName = $username
    displayname = $displayname
    preferredLanguage = "nl-NL"
    active = $False
    emails = @{
                value = $email
                type = "work"
                primary = $True
        }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if(-Not($dryRun -eq $True)){
 try {
    $create = $True;
    $authorizationurl = "https://identitymanagement.services.iprova.nl:443/oauth/token"
    $authorizationbody = @{
        "grant_type" =  $grant_type
        "client_id" =  $client_id
        "client_secret" = $client_secret
        "token_expiration_disabled" =  $false
    }
    $authorizationbody = $authorizationbody | ConvertTo-Json

    $AccessToken = Invoke-RestMethod -uri $authorizationurl -body $authorizationbody -Method Post -ContentType "application/json"

    $headers = @{
        Authorization = "$($AccessToken.token_type) $($AccessToken.access_token)"
    }

    try{
        $body = $account | ConvertTo-Json

        $resp = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -body $body -ContentType 'application/json'
        write-verbose -Verbose $resp
        $body = $account | ConvertTo-Json -Depth 10 
            if(-Not($null -eq $resp.id)){
                $aRef = $resp.id
                $success = $True;
                $auditMessage = "created succesfully";
            }
        }
    catch{
        $failure = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($failure)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd() | convertFrom-Json;
        if($errResponse.detail -like '*User with given login_code already exists*'){
            $correlationurl = "https://identitymanagement.services.iprova.nl/scim/users?filter=username%20eq%20%22" + $username + '%22'
            $resp = Invoke-RestMethod -Method Get -Uri $correlationurl -Headers $headers
            if(-Not($null -eq $resp) -and -Not($null -eq $resp.resources.id)) {
                $aRef = $resp.resources.id 
                $create = $False;
                $success = $True;
                $auditMessage = "Correlation found record $($username) update succesfully";
            }
        }    }
    }catch{

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd()| convertFrom-Json;
        $auditMessage = "not created succesfully: ${errResponse}";
    }
}
else{
        $authorizationurl = "https://identitymanagement.services.iprova.nl:443/oauth/token"
        $authorizationbody = @{
            "grant_type" =  $grant_type
            "client_id" =  $client_id
            "client_secret" = $client_secret
            "token_expiration_disabled" =  $false
        }
        $authorizationbody = $authorizationbody | ConvertTo-Json

        $AccessToken = Invoke-RestMethod -uri $authorizationurl -body $authorizationbody -Method Post -ContentType "application/json"

        $headers = @{
            Authorization = "$($AccessToken.token_type) $($AccessToken.access_token)"
        }
        
        $correlationurl = "https://identitymanagement.services.iprova.nl/scim/users?filter=username%20eq%20%22" + $username + '%22'
        $resp = Invoke-RestMethod -Method Get -Uri $correlationurl -Headers $headers
        if(-Not($null -eq $resp) -and -Not($null -eq $resp.resources.id)) {
             $aRef = $resp.resources.id 
             $create = $False;
             $auditMessage = "Correlation found record $($username) update succesfully";
             
         }
         else{
             Write-Verbose -Verbose "Username $username is available in iProva"
         }
}


#build up result
$result = [PSCustomObject]@{ 
	Success= $success;
    AccountReference= $aRef;
	AuditDetails=$auditMessage;
    Account= $account;
};

Write-Output $result | ConvertTo-Json -Depth 10;
