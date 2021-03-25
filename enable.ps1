$config = ConvertFrom-Json $configuration;

#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json;
$auditMessage = " not enabled succesfully";

#iProva system data
$url = $config.url
$grant_type = 'client_credentials'
$client_id = $config.clientid
$client_secret = $config.clientsecret

#mapping
$account = @{
    id = $aRef
     operations = @{
                op = "replace"
                path = "active"
                value = $True
        }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try{
    if(-Not($dryRun -eq $True)){
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
        
        $useruri = $url + $aRef
        $body = $account | ConvertTo-Json
        $resp = Invoke-RestMethod -Method PATCH -Uri $useruri -Headers $headers -body $body -ContentType 'application/json'
        $body = $account | ConvertTo-Json -Depth 10 
        $success = $True;
        $auditMessage = "account enabled successfully";}
    }catch{
        if(-Not($_.Exception.Response -eq $null)){
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $errResponse = $reader.ReadToEnd();
            $auditMessage = " : ${errResponse}";
    }else {
            $auditMessage = " : General error";
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
