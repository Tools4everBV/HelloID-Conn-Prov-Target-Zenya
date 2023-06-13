| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />

<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/zenya-logo.png">
</p

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.1.3   | Added support to set title, manager and department | 2022/10/12  |
| 1.1.2   | Updated with http error resolving | 2022/08/23  |
| 1.1.1   | Updated with new logging | 2022/08/13  |
| 1.1.0   | Updated with new logging and added group management | 2022/07/12  |
| 1.0.0   | Initial release | 2020/08/06  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Versioning](#versioning)
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#getting-started)
  - [Connection settings](#connection-settings)
  - [Prerequisites](#prerequisites)
  - [Remarks](#remarks)
- [Getting help](#getting-help)
- [HelloID docs](#helloid-docs)

## Introduction
_HelloID-Conn-Prov-Target-Zenya is a _target_ connector. Zenya (formerly known as iProva) provides a set of API's that allow you to programmatically interact with it's data. The Zenya API is a scim (http://www.simplecloud.info) API. The HelloID connector allows you to create and manage Zenya accounts. Using entitlements it is possible to add account to groups.
More information about supported API actions can be found on: https://identitymanagement.services.iprova.nl/swagger-ui/

> Note that this connector is limited to the available functionalitiy of the SCIM API.
 - > We can only manage groups we actually created with HelloID. So only the groups we created through HelloID Resource Creation.
   - > Note that HelloID can __only create groups__. The groups will __not be deleted by HelloID__.
 - > We can only set a department that already exists in Zenya. 
   - > For this, all departments must have a unique name (we can only match on name, so matching on code (or any other field) is not possible) within the entire tree (i.e., no duplicate names anywhere).
   - >In addition, maintenance of the departments (i.e., creating/deleting as well as setting the owner) will need to take place within Zenya.
 - > We can only set a manager that exists in Zenya and has been created by HelloID. For this, HelloID has to have granted the Account entitlement for the manager first.
  

> Also please keep in mind that after you have created and tested the connector Infoland has to set the current users in scope of the synchronisation, if this is not done by Infoland every user will get a new account since accounts are connected to the connector.

> Since we user the SCIM API we cannot create/set the password of users, so SSO is required to manage the users using the SCIM API.

The HelloID connector consists of the template scripts shown in the following table.

| Action                          | Action(s) Performed                           | Comment   | 
| ------------------------------- | --------------------------------------------- | --------- |
| create.ps1                      | Correlate or create Zenya user                |           |
| update.ps1                      | Update Zenya user                             |           |
| enable.ps1                      | Enable Zenya user                             |           |
| disable.ps1                     | Disable Zenya user                            |           |
| delete.ps1                      | Delete Zenya user                             | Be careful when implementing this! There is no way to restore deleted users.  |
| resourceCreation.groups.departments.ps1  | Create Zenya groups for all departments in HelloID  | This specific example uses the department objects as input. Please customize the script accordingly when using other input.  |
| permissions.groups.ps1  | Query the groups in Zenya          | We can only query the groups in Zenya that HelloID has created. So creating the groups through Resource Creation is a requirement to manage the groups |
| grantPermission.groups.ps1         | Grant a Zenya user to a Zenya group  | We can only update the groups in Zenya that HelloID has created. So creating the groups through Resource Creation is a requirement to manage the groups |
| revokePermission.groups.ps1         | Revoke a Zenya user to a Zenya group  | We can only update the groups in Zenya that HelloID has created. So creating the groups through Resource Creation is a requirement to manage the groups |

<!-- GETTING STARTED -->
## Getting started
### Connection settings
The following settings are required to connect to the API.

| Setting               | Description                                                       | Mandatory   |
| --------------------- | ----------------------------------------------------------------- | ----------- |
| Service Address       | The Service Address of the SCIM API                               | Yes         |
| Client ID             | The OAuth2 Client ID to connect to the SCIM API                   | Yes         |
| Client Secret         | The OAuth2 Client Secret to connect to the SCIM API               | Yes         |
| Toggle debug logging | When toggled, extra logging is shown. Note that this is only meant for debugging, please switch this off when in production. | No         |

### Prerequisites
- Zenya environment
- SSO for Zenya environment
- Registered Provider in Zenya. Please see the Zenya Documentation (step 3) for the "How To": [Create Provider in Zenya](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1). The following values are needed to connect
  - Service Address
  - Client ID
  - Client Secret

### Remarks
 - > We can only manage groups we actually created with HelloID. So only the groups we created through HelloID Resource Creation.
   - > Note that HelloID can __only create groups__. The groups will __not be deleted by HelloID__.
 - > We can only set a department that already exists in Zenya. 
   - > For this, all departments must have a unique name (we can only match on name, so matching on code (or any other field) is not possible) within the entire tree (i.e., no duplicate names anywhere).
   - >In addition, maintenance of the departments (i.e., creating/deleting as well as setting the owner) will need to take place within Zenya.
 - > We can only set a manager that exists in Zenya and has been created by HelloID. For this, HelloID has to have granted the Account entitlement for the manager first.

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
