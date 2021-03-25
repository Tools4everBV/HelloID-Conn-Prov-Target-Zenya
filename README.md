# HelloID-Conn-Prov-Target-iProva

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
Currently this connector can be used to create users in Infoland iProva through the available SCIM API. Currently only users are supported.
More information about supported API actions can be found on: https://identitymanagement.services.iprova.nl/swagger-ui/

This example requires that the usernames in iProva are equal to the employeenumber of the user. This is done in combination with a single-sign-on solution
where it does not really matter what the username of a user is since they do not have to enter it at all and it is not visible in iProva.
If a employeenumber already exists it will fail and automatically correlate the account. Unfortunately it is not possible to retreive a user based on identifier
in the iProva API. Also please keep in mind that after you have created and tested the connector Infoland has to set the current users in scope of the synchronisation, 
if this is not done by Infoland every user will get a new account since accounts are connected to the connector.

<!-- GETTING STARTED -->
## Getting Started

By using this connector you will have the ability to create, update and delete accounts from the Infoland iProva system.

Connecting to iProva is possible with a client_id and client_secret provided by Infoland

<!-- USAGE EXAMPLES -->
## Setup the PowerShell connector

1. Add a new 'Target System' to HelloID and make sure to import all the necessary files.

    - [ ] configuration.json
    - [ ] create.ps1
    - [ ] enable.ps1
    - [ ] disable.ps1
    - [ ] update.ps1    

2. Fill in the required fields on the 'Configuration' tab.
3. Change the source for the e-mailaddress. Currently data from Gsuite is used.
_For more information about our HelloID PowerShell connectors, please refer to our general [Documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-How-to-configure-a-custom-PowerShell-target-connector) page_
