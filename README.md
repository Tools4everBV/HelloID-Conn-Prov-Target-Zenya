# HelloID-Conn-Prov-Target-Zenya

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />

<p align="center">
  <img src="https://user-images.githubusercontent.com/69046642/177937093-8bf6f838-5026-4d44-a3fb-1fdd1006fced.png">
</p

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Introduction](#introduction)
* [Getting Started](#getting-started)
  * [Source](#source)
  * [Target](#target)
  * [Mappings](#mappings)
  * [Scope](#scope)
* [Setup the PowerShell connector](#setup-the-powershell-connector)


## Introduction
Currently this connector can be used to create users in Infoland Zenya (formerly known as iProva) through the available SCIM API. Currently only users are supported.
More information about supported API actions can be found on: https://identitymanagement.services.iprova.nl/swagger-ui/

This example requires that the usernames in Zenya are equal to the employeenumber of the user. This is done in combination with a single-sign-on solution
where it does not really matter what the username of a user is since they do not have to enter it at all and it is not visible in Zenya.
Also please keep in mind that after you have created and tested the connector Infoland has to set the current users in scope of the synchronisation, 
if this is not done by Infoland every user will get a new account since accounts are connected to the connector.

<!-- GETTING STARTED -->
## Getting Started

By using this connector you will have the ability to create, enable, disable, update and delete accounts from the Infoland enya system.

Connecting to Zenya is possible with a client_id and client_secret provided by Infoland

<!-- USAGE EXAMPLES -->
## Setup the PowerShell connector

1. Add a new 'Target System' to HelloID and make sure to import all the necessary files.

    - [ ] configuration.json
    - [ ] create.ps1
    - [ ] enable.ps1
    - [ ] disable.ps1
    - [ ] update.ps1
    - [ ] delete.ps1  

2. Fill in the required fields on the 'Configuration' tab.

_For more information about our HelloID PowerShell connectors, please refer to our general [Documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-How-to-configure-a-custom-PowerShell-target-connector) page_

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
