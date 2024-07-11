# HelloID-Conn-Prov-Target-Zenya
Repository for HelloID Provisioning Target Connector to Zenya using the SCIM API

<a href="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber/network/members"><img src="https://img.shields.io/github/forks/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber" alt="Forks Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber/pulls"><img src="https://img.shields.io/github/issues-pr/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber" alt="Pull Requests Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber/issues"><img src="https://img.shields.io/github/issues/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber" alt="Issues Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Tools4everBV/HelloID-Conn-Prov-Target-MicrosoftTeams-DirectRoutingPhonenumber?color=2b9348"></a>

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                       |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/zenya-logo.png">
</p

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Target-Zenya](#helloid-conn-prov-target-zenya)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
    - [SCIM based API](#scim-based-api)
    - [Available actions](#available-actions)
    - [Mapping](#mapping)
    - [Correlation](#correlation)
  - [Getting started](#getting-started)
    - [Create Provider in Zenya](#create-provider-in-zenya)
    - [Allowing user and groups created by Zenya to be returned in the SCIM service](#allowing-user-and-groups-created-by-zenya-to-be-returned-in-the-scim-service)
    - [Connection settings](#connection-settings)
    - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Requirements
- **SSO** configured on Zenya environment
- A **Registered Provider in Zenya**. Please see the Zenya Documentation (step 3) for the "How To": [Create Provider in Zenya](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1).
  - Service Address
  - Client ID
  - Client Secret
- **Concurrent sessions** in HelloID set to a **maximum of 2**! Exceeding this limit may result in timeout errors, as the Zenya SCIM API supports only a specific number of requests per minute.

## Introduction
For this connector we have the option to create and manage Zenya user accounts and groups.

### SCIM based API
SCIM stands for _System for Cross-domain Identity Management_. It is an open standard protocol that simplifies the management of user identities and related information across different systems and domains. For more information, please see: http://www.simplecloud.info

The HelloID connector uses the API endpoints listed in the table below.

| Endpoint     | Description                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------------- |
| /scim/users  | API docs for Get Request: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUsersRequest  |
| /scim/groups | API docs for Get Request: https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetgroupsRequest |

### Available actions
The HelloID connector consists of the template scripts shown in the following table.

| Action                 | Action(s) Performed                                    | Comment                                                                      |
| ---------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| create.ps1             | Create (or update) and correlate a user account.       |                                                                              |
| enable.ps1             | Enable a user account                                  |                                                                              |
| update.ps1             | Update a user account                                  |                                                                              |
| disable.ps1            | Disable a user account                                 |                                                                              |
| delete.ps1             | Delete a user account                                  | Be careful when implementing this! There is no way to restore deleted users. |
| permissions.ps1        | Retrieves all groups and provides them as entitlements |                                                                              |
| grantPermission.ps1    | Add a user account to a group                          |                                                                              |
| revokePermission.ps1   | Remove a user account from a group                     |                                                                              |
| dynamicPermissions.ps1 | Add/remove a user account to/from a group              |                                                                              |
| resourceCreation.ps1   | Create a group for provided resource, e.g. department  |                                                                              |

### Mapping
The mandatory and recommended field mapping is listed below.

| Name        | Type  | Create | Enable | Update | Disable | Delete | Use in Notifications | Store in account data | Default mapping                                                                  | Mandatory | Comment                                                                                                                        |
| ----------- | ----- | ------ | ------ | ------ | ------- | ------ | -------------------- | --------------------- | -------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Active      | Text  | X      | X      |        | X       |        | No                   | Yes                   | For create: Fixed: False<br>For enable: Fixed: True<br>For disable: Fixed: False | Yes       |                                                                                                                                |
| Department  | Text  | X      |        | X      |         |        | No                   | Yes                   | Field: PrimaryContract.Department.DisplayName                                    | No        | Custom scripting in code to transform this to the corresponding scim object                                                    |
| DisplayName | Text  | X      |        | X      |         |        | No                   | Yes                   | Complex: [displayName.js](mapping/displayName.js)                                | Yes       |                                                                                                                                |
| Emails      | Array | X      |        | X      |         |        | No                   | Yes                   | Complex: [emails.js](mapping/emails.js)                                          | Yes       | Custom scripting in code to transform this to the corresponding scim object                                                    |
| ExternalId  | Text  | X      |        | X      |         |        | No                   | Yes                   | Field: ExternalId                                                                | Yes       |                                                                                                                                |
| Manager     | Text  | X      |        | X      |         |        | No                   | Yes                   | None                                                                             | No        | Set within script, as the aRef of manager is used. Custom scripting in code to transform this to the corresponding scim object |
| Title       | Text  | X      |        | X      |         |        | No                   | Yes                   | Field: PrimaryContract.Title.Name                                                | No        |                                                                                                                                |
| Username    | Text  | X      |        | X      |         |        | No                   | Yes                   | Complex: [username.js](mapping/username.js)                                      | Yes       | Used for correlation                                                                                                           |

### Correlation
| Correlation field         | Selection | Comment                                                                                                 |
| ------------------------- | --------- | ------------------------------------------------------------------------------------------------------- |
| Person Correlation field  | None      | No selection, as this isn't used. Only the Account correlation field is used.                           |
| Account Correlation field | Username  | ExternalId isn't available to query users on, therefore only username can be used as correlation field. |

<!-- GETTING STARTED -->
## Getting started

### Create Provider in Zenya
Please follow the Zenya Documentation (step 3) to [Create a Provider in Zenya](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1)

### Allowing user and groups created by Zenya to be returned in the SCIM service
By default, ONLY groups and users created by the identity provider or linked to it are returned in the SCIM service. However, there is a setting that Infoland can enable per provider, allowing the users and groups created by Zenya to be returned as well. If users/groups come from multiple sources (ADs, created within Zenya itself), please contact Infoland to ensure that the SCIM service returns everything, not just the users/groups synchronized through this process.
For more information, please see (step 7): https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1

### Connection settings
The following settings are required to connect to the API.

| Setting              | Description                                                                                                                  | Mandatory |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------- |
| Service Address      | The Service Address of the SCIM API                                                                                          | Yes       |
| Client ID            | The OAuth2 Client ID to connect to the SCIM API                                                                              | Yes       |
| Client Secret        | The OAuth2 Client Secret to connect to the SCIM API                                                                          | Yes       |
| Toggle debug logging | When toggled, extra logging is shown. Note that this is only meant for debugging, please switch this off when in production. | No        |


### Remarks
- Infoland must define the current users within the synchronization scope. Failure to do so will result in every person being assigned a new user account.
- Since we use the SCIM API, we cannot create/set the password of users, so Single Sign-On (SSO) is required to manage the users using the SCIM API.
- Currently, we can only manage groups we actually created with HelloID. So only the groups we created through HelloID Resource Creation.
  - Note that HelloID can only create groups. The groups will not be deleted by HelloID.
- Currently, we can only set a department that already exists in Zenya.
  - For this, all departments must have a unique name (we can only match on name, so matching on code or any other field is not possible) within the entire tree (i.e., no duplicate names anywhere).
  - In addition, maintenance of the departments (i.e., creating/deleting as well as setting the owner) will need to take place within Zenya.
- Currently, we can only set a manager that exists in Zenya and has been created by HelloID. For this, HelloID has to have granted the Account entitlement for the manager first.

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
