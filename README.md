# HelloID-Conn-Prov-Target-Zenya

> [!IMPORTANT]
> This repository contains only the connector and configuration code. The implementer is responsible for acquiring connection details such as the username, password, certificate, etc. You may also need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-Zenya/blob/main/Logo.png?raw=true" alt="Zenya Logo">
</p>

## Table of Contents

- [HelloID-Conn-Prov-Target-Zenya](#helloid-conn-prov-target-zenya)
  - [Table of Contents](#table-of-contents)
  - [Supported  features](#supported--features)
  - [Requirements](#requirements)
  - [Remarks](#remarks)
    - [Department Management](#department-management)
    - [SCIM API Limitations](#scim-api-limitations)
    - [Manager Field in Field Mapping](#manager-field-in-field-mapping)
  - [Introduction](#introduction)
  - [Getting Started](#getting-started)
    - [Create a Provider in Zenya](#create-a-provider-in-zenya)
    - [Allowing Users and Groups Created by Zenya to Be Returned in the SCIM Service](#allowing-users-and-groups-created-by-zenya-to-be-returned-in-the-scim-service)
    - [Provisioning PowerShell V2 connector](#provisioning-powershell-v2-connector)
      - [Correlation Configuration](#correlation-configuration)
      - [Field mapping](#field-mapping)
    - [Connection Settings](#connection-settings)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Supported  features

The following features are available:

| Feature                             | Supported | Actions                                 | Remarks            |
| ----------------------------------- | --------- | --------------------------------------- | ------------------ |
| **Account Lifecycle**               | ✅         | Create, Update, Enable, Disable, Delete |                    |
| **Permissions**                     | ✅         | Retrieve, Grant, Revoke                 | Static and Dynamic |
| **Resources**                       | ✅         | -                                       |                    |
| **Entitlement Import: Accounts**    | ✅         | -                                       |                    |
| **Entitlement Import: Permissions** | ❌         | -                                       |                    |

## Requirements

- **SSO Configuration**: Ensure SSO is configured in the Zenya environment.
- **Registered Provider in Zenya**: Refer to the Zenya documentation for detailed instructions: [Create Provider in Zenya](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1).
  - Service Address
  - Client ID
  - Client Secret
- **Concurrent Sessions**: Limit HelloID concurrent sessions to a maximum of 2 to avoid timeout errors, as the Zenya SCIM API has a rate limit on the number of requests per minute.

## Remarks

### Department Management

- In Zenya, department names must be unique across the entire hierarchy. Matching is done based on the department name alone, so any duplicates, even in different parts of the structure, will cause issues.

### SCIM API Limitations

- The Zenya SCIM API does not allow for setting or managing user passwords, so Single Sign-On (SSO) is required for user management.

- By default, the SCIM service only returns users and groups that were created by the identity provider or are linked to it. However, Infoland can enable a setting that allows users and groups created within Zenya to be included as well.

- This is particularly important if your users or groups come from multiple sources, such as Active Directory or Zenya itself. To ensure the SCIM service returns all relevant data—not just the users and groups synchronized through HelloID—contact Infoland to configure this setting properly.

- For more information, refer to step 7 in the Zenya documentation: [Zenya Documentation](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1).

### Manager Field in Field Mapping

- The `Manager` field is optional and represents the manager's ID for the user. This field is read-only.

- **Note:** The `Manager` field uses a "None" mapping because the value is calculated within the scripts. We can only assign a manager who exists in Zenya and was created by HelloID. Before assigning a manager, HelloID must first grant the Account entitlement to the manager.

## Introduction

This connector allows you to update employee information in SDB HR. It is primarily used to write back the email address that HelloID generates for systems like Active Directory or Azure Active Directory.

The following API endpoints are utilized by this connector:

| Endpoint                                                                                               | Description          |
| ------------------------------------------------------------------------------------------------------ | -------------------- |
| [/scim/users](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUsersRequest)        | Get users (GET)      |
| [/scim/users](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PostUserRequest)        | Create user (POST)   |
| [/scim/users/{id}](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchUser)         | Update user (PATCH)  |
| [/scim/users/{id}](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/DeleteUserRequest) | Delete user (DELETE) |
| [/scim/groups](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetGroupsRequest)      | Get groups (GET)     |
| [/scim/groups](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PostGroupRequest)      | Create group (POST)  |
| [/scim/groups/{id}](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/PatchGroup)       | Update group (PATCH) |

## Getting Started

### Create a Provider in Zenya

To start using the HelloID-Zenya connector, you first need to create a provider in Zenya. Follow these steps:

1. **Access the Zenya Documentation**:
   - Go to the [Zenya Documentation](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1).

2. **Follow Step 3**:
   - Navigate to **Step 3** in the documentation, which provides detailed instructions on how to create a provider in Zenya.
   - Complete the setup by taking note of the required information, including the **Service Address**, **Client ID**, and **Client Secret**.

### Allowing Users and Groups Created by Zenya to Be Returned in the SCIM Service

By default, the SCIM service only returns users and groups that were created by the identity provider or linked to it. However, you can configure Zenya to also return users and groups that were created within Zenya itself.

Follow these steps:

1. **Contact Infoland**:
   - Reach out to Infoland to request that the SCIM service returns all users and groups, not just those synchronized through the identity provider.

2. **Enable SCIM Service Setting**:
   - Ensure that the setting to include Zenya-created users and groups in the SCIM service is enabled. This is particularly important if your environment includes users and groups from multiple sources, such as Active Directory and Zenya itself.

3. **Verify Configuration**:
   - After Infoland enables this setting, verify that all necessary users and groups are being returned by the SCIM service.

For more detailed information, refer to [Step 7 of the Zenya Documentation](https://webshare.zenya.work/DocumentResource/709a648d-6300-4e42-a2a6-54ae02201873/Document.pdf?webshareid=y491fqpfwxhoo0kd&showinlinepdf=1).

### Provisioning PowerShell V2 connector

#### Correlation Configuration
The correlation configuration specifies which properties are used to match accounts in Zenya with users in HelloID.

To properly set up the correlation:

1. Open the `Correlation` tab.

2. Specify the following configuration:

    | Setting                       | Value      |
    | ----------------------------- | ---------- |
    | **Person Correlation Field**  | `UserName` |
    | **Account Correlation Field** | `Username` |

> [!IMPORTANT]
> Currently, the **Person Correlation Field** (`UserName`) is not used in the correlation process. Only the **Account Correlation Field** (`Username`) is active because `ExternalId` cannot be queried via the SCIM API. 
> 
> **However**, configuring the **Person Correlation Field** is advisable to prepare for future updates, such as the upcoming Governance Module. This module will require person-to-account mappings, so setting this field now helps ensure readiness for future features.
> 
> Ensure the **Account Correlation Field** is set to `Username` to align with the SCIM API's capabilities. Verify that your setup is supported by the [SCIM API documentation](https://identitymanagement.services.iprova.nl/swagger-ui/#!/scim/GetUsersRequest).

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

#### Field mapping
The field mapping can be imported by using the _fieldMapping.json_ file.

### Connection Settings

The following settings are required to connect to the Zenya SCIM API:

| Setting                     | Description                                                                                                                                                                                                                                                                      | Mandatory |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| **Service Address**         | The URL of the SCIM API service.                                                                                                                                                                                                                                                 | Yes       |
| **Client ID**               | The OAuth2 Client ID used to authenticate with the SCIM API.                                                                                                                                                                                                                     | Yes       |
| **Client Secret**           | The OAuth2 Client Secret used to authenticate with the SCIM API.                                                                                                                                                                                                                 | Yes       |
| **Set Department in Zenya** | When enabled, this setting will map and set the department value. Note: Only departments that already exist in Zenya can be assigned, and all department names must be unique. Department maintenance (creation, deletion, and owner assignment) must be done directly in Zenya. | No        |
| **Set Manager in Zenya**    | When enabled, this setting will map and set the manager value. Note: Only managers who exist in Zenya and were created by HelloID can be assigned. Ensure HelloID has granted the Account entitlement to the manager beforehand.                                                 | No        |
| T**oggle debug logging**    | Displays debug logging when toggled. **Switch off in production**                                                                                                                                                                                                                | No        |

## Getting help
> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
