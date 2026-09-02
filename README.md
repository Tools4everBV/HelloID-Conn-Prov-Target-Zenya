# HelloID-Conn-Prov-Target-Zenya

> [!IMPORTANT]
> This repository contains only the connector and configuration code. The implementer is responsible for acquiring connection details such as the username, password, certificate, etc. You may also need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Zenya/blob/main/Logo.png?raw=true" alt="Zenya Logo">
</p>

## Table of contents
 
- [HelloID-Conn-Prov-Target-Zenya](#helloid-conn-prov-target-zenya)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Supported features](#supported-features)
  - [Getting started](#getting-started)
    - [HelloID Icon URL](#helloid-icon-url)
    - [Requirements](#requirements)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
  - [Remarks](#remarks)
    - [Department Management](#department-management)
    - [Permission Management](#permission-management)
    - [SCIM API Limitations](#scim-api-limitations)
    - [Manager Field in Field Mapping](#manager-field-in-field-mapping)
  - [Development resources](#development-resources)
    - [API endpoints](#api-endpoints)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-Zenya_ is a target connector. It uses SCIM and REST APIs to manage user accounts, user groups, and permissions in Zenya.


## Supported features

The following features are available:

| Feature                                   | Supported | Actions                                 | Remarks                               |
|-------------------------------------------|-----------|-----------------------------------------|---------------------------------------|
| **Account Lifecycle**                     | ✅         | Create, Update, Enable, Disable, Delete |                                       |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke                 | Static and Dynamic                    |
| **Resources**                             | ✅         | Create                                  | User Groups from contract departments |
| **Entitlement Import: Accounts**          | ✅         | -                                       |                                       |
| **Entitlement Import: Permissions**       | ✅⚠️       | -                                       |                                       |
| **Governance Reconciliation Resolutions** | ✅         | Disable, Delete                         |                                       |

### ⚠️ Entitlement Import: Permissions
Because the scope of the SCIM and REST API differs, Zenya can return permissions via the REST API related to accounts that cannot be found by HelloID via the SCIM API. This results in a warning in the target snapshot.

## Getting started

### HelloID Icon URL

URL of the icon used for the HelloID Provisioning target system:

```
https://raw.githubusercontent.com/Tools4everBV/HelloID-Conn-Prov-Target-Zenya/refs/heads/main/Icon.png
```

### Requirements

- **SSO configuration**: Configure SSO in the Zenya environment before managing users through this connector.

- **SCIM provider in Zenya**: Create a dedicated SCIM provider for HelloID in Zenya.

- **Migrating an existing user-management source**: Disconnect the existing SCIM provider, i+Sync task, or other external user-management source without deleting users or groups. Verify that the existing users and groups remain in Zenya with a blue user or group icon. Create the HelloID SCIM provider and start provisioning users. HelloID will attempt to create each existing user and receive a user-name conflict. Link the existing user to the HelloID provider in the Zenya UI, then retry the HelloID action. HelloID can then correlate and manage the user. Contact the Zenya servicedesk when assistance is required for this migration.

### Connection settings

The following settings are required to connect to the Zenya APIs.

| Setting          | Description                                                      | Mandatory                                      |
|------------------|------------------------------------------------------------------|------------------------------------------------|
| ScimBaseUrl      | Base URL of the SCIM endpoint                                    | Yes                                            |
| ScimClientId     | Client ID of the Zenya provider for external user management     | Yes                                            |
| ScimClientSecret | Client secret of the Zenya provider for external user management | Yes                                            |
| SetDepartment    | Whether to set the department in Zenya                           | No                                             |
| SetManager       | Whether to set the manager in Zenya                              | No                                             |
| ApiBaseUrl       | Base URL of the Zenya REST API                                   | Yes, when permissions or group resources apply |
| ApiClientId      | Client ID of the registered Zenya REST API application           | Yes, when permissions or group resources apply |
| ApiClientSecret  | Client secret of the registered Zenya REST API application       | Yes, when permissions or group resources apply |

SCIM credentials are used for account lifecycle operations and account entitlement import. REST API credentials are used for permission management, permission entitlement import, and group resources.

> [!IMPORTANT]
> **Concurrent sessions**
>
> Limit HelloID concurrent sessions to a maximum of 2 to avoid timeouts caused by the Zenya SCIM API rate limit.

### Correlation configuration

The correlation configuration specifies which properties are used to match accounts in Zenya with users in HelloID.

To properly set up the correlation:

1. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                       | Value                        |
    |-------------------------------|------------------------------|
    | **Person Correlation Field**  | `Accounts.UserPrincipalName` |
    | **Account Correlation Field** | `Username`                   |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping
The field mapping can be imported by using the _fieldMapping.json_ file.

## Remarks

### Department Management

- In Zenya, department names must be unique across the entire hierarchy. Matching is done based on the department name alone, so any duplicates, even in different parts of the structure, will cause issues.

### Permission Management

- The current subpermission script manages only the group membership changes that are initiated by HelloID. Manual changes are not detected.

### SCIM API Limitations

- The Zenya SCIM API does not allow for setting or managing user passwords, so Single Sign-On (SSO) is required for user management.

- The SCIM service returns only users created by, or linked to, the configured identity provider. Users created manually in Zenya or through another provider are not available to HelloID for correlation until they are linked to the HelloID provider.

> [!IMPORTANT]
> **Provider Migration Required**
> 
> Before HelloID takes over existing users and groups, disconnect the previous user-management source without deleting its objects. For a SCIM provider, select **Ontkoppelen** when removing the provider. For i+Sync, remove the users and groups from the synchronization task before deleting the task. Verify that the objects remain in Zenya with a blue user or group icon, then create the HelloID SCIM provider.
> 
> An unlinked user retains its user name, so HelloID first receives a user-name conflict when it attempts to create the existing user. Link the user to the HelloID provider in the Zenya UI, then retry the HelloID action; HelloID can then correlate and manage the account.

The same provider-linking approach is not available for user groups and their memberships, because groups are not exclusively managed by a SCIM provider. The connector therefore uses the REST API for group management and group membership imports. The REST API also has access to groups created in the Zenya UI.

As a result, the REST API can return group memberships for users that are not returned by the SCIM API. HelloID cannot correlate those memberships because the corresponding accounts are absent from the account entitlement import. Only memberships for users visible through the configured SCIM provider can be correlated.

Group resources must also use the REST API, because the REST API used for permissions cannot modify groups created through SCIM.

### Manager Field in Field Mapping

- The `Manager` field is optional and represents the manager's ID for the user. This field is read-only.

- **Note:** The `Manager` field uses a "None" mapping because the value is calculated within the scripts. We can only assign a manager who exists in Zenya and was created by HelloID. Before assigning a manager, HelloID must first grant the Account entitlement to the manager.


## Development resources

### API endpoints

The following endpoints are used by the connector. The host names are configured through `ScimBaseUrl` and `ApiBaseUrl`.

| Endpoint                             | HTTP method        | Description                                 |
|--------------------------------------|--------------------|---------------------------------------------|
| `ScimBaseUrl/oauth/token`            | POST               | Obtain a SCIM access token                  |
| `ScimBaseUrl/scim/users`             | GET, POST          | Retrieve and create user accounts           |
| `ScimBaseUrl/scim/users/{id}`        | GET, PATCH, DELETE | Retrieve, update, and delete a user account |
| `ApiBaseUrl/api/oauth/token`         | POST               | Obtain a REST API access token              |
| `ApiBaseUrl/api/user_groups`         | GET, POST          | Retrieve and create user groups             |
| `ApiBaseUrl/api/user_groups/{id}`    | PATCH              | Update a user group and its memberships     |
| `ApiBaseUrl/api/user_groups/members` | GET                | Retrieve user group memberships             |

### API documentation

- [Zenya REST API Swagger documentation](https://swagger.zenya-dev.nl/api/swagger/index.html)

Create a REST API application in Zenya when permission management or group resources are enabled. The application provides the REST API credentials and its Zenya user must have permission to maintain user groups.

## Getting help
> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
