  <p align="center">
  <img src="./assets/policyweaver.png" alt="Policy Weaver icon" width="200"/>
</p>

</p>
<p align="center">
<a href="https://badgen.net/github/license/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/license/microsoft/Policy-Weaver" alt="License">
</a>
<a href="https://badgen.net/github/releases/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/releases/microsoft/Policy-Weaver" alt="Test">
</a>
<a href="https://badgen.net/github/contributors/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/contributors/microsoft/Policy-Weaver" alt="Publish">
</a>
<a href="https://badgen.net/github/commits/microsoft/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/github/commits/microsoft/Policy-Weaver" alt="Commits">
</a>
<a href="https://badgen.net/pypi/v/Policy-Weaver" target="_blank">
    <img src="https://badgen.net/pypi/v/Policy-Weaver" alt="Package version">
</a>
</p>

---

# Policy Weaver: synchronizes data access policies across platforms

A Python-based accelerator designed to automate the synchronization of security policies from different source catalogs with [OneLake Security](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles) roles. While mirroring is only synchronizing the data, **Policy Weaver** is adding the missing piece which is mirroring data access policies to ensure consistent security across data platforms.


## :rocket: Features
- **Microsoft Fabric Support**: Direct integration with Fabric Mirrored Databases/Catalogs and OneLake Security.
- **Runs anywhere**: It can be run within Fabric Notebook or from anywhere with a Python runtime.
- **Effective Policies**: Resolves effective read privileges automatically, traversing nested groups and roles as required.
- **Pluggable Framework**: Supports Azure Databricks and Snowflake policies, with more connectors planned.
- **Secure**: Can use Azure Key Vault to securely manage sensitive information like Service Principal credentials and API tokens.

> :pushpin: **Note:** Row-level and column-level security extraction will be implemented in the next version, once these features become available in OneLake Security.


## :hammer_and_wrench: Installation
Make sure your Python version is greater or equal than 3.11. Then, install the library:
```bash
$ pip install policy-weaver
```

# :rocket: Getting Started

Follow the General Prerequisites and Installation steps below [here](#clipboard-general-prerequisites). Then, depending on your source catalog, follow the specific setup instructions for either [Databricks](#thread-databricks-specific-setup) or [Snowflake](#thread-snowflake-specific-setup).

## :clipboard: General Prerequisites
Before installing and running this solution, ensure you have:
- **Azure [Service Principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)** with the following [Microsoft Graph API permissions](https://learn.microsoft.com/en-us/graph/permissions-reference) (*This is not mandatory in every case but recommended, please check the specific source catalog requirements and limitations*):
  - `User.Read.All` as application permissions
- [A client secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-3-create-a-new-client-secret) for the Service Principal
- Added the Service Principal as [Contributor](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces) on the Fabric Workspace containing the mirrored database/catalog.

> :pushpin: **Note:** Every source catalog has additional pre-requisites



## :thread: Databricks specific setup

### Azure Databricks Configuration
We assume you have an Entra ID integrated Unity Catalog in your Azure Databricks workspace. To set up Entra ID SCIM for Unity Catalog, please follow the steps in [Configure Entra ID SCIM for Unity Catalog](https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/scim/aad).

:clipboard: Note that we only sync groups, users and service principals on account level, i.e. specifically no legacy "local" workspace groups. If you still use local workspace groups, please migrate them: [Link to Documentation](https://learn.microsoft.com/en-us/azure/databricks/admin/users-groups/workspace-local-groups)

We also assume you already have a mirrored catalog in Microsoft Fabric. If not, please follow the steps in [Create a mirrored catalog in Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/onelake/mirror-azure-databricks-catalog). You need to enable One Lake Security by opening the Item in the Fabric UI and click on "Manage OneLake data access".


<img width="570" height="268" alt="image" src="https://github.com/user-attachments/assets/462e8123-5929-427e-9408-31df95d44a15" />


To allow Policy Weaver to read the Unity Catalog metadata and access policies, you need to assign the following roles to your Azure Service Principal:
1. Go to the Account Admin Console (https://accounts.azuredatabricks.net/) :arrow_right: User Management :arrow_right: Add your Azure Service Principal. 
1. Click on the Service Principal and go to the Roles tab :arrow_right: Assign the role "Account Admin"
3. Go to the "Credentials & Secrets" tab :arrow_right: Generate an OAuth Secret. Save the secret, you will need it in your config.yaml file as the `account_api_token`.

### Update your Configuration file
Download this [config.yaml](./config.yaml) file template and update it based on your environment.

For Databricks specifically, you will need to provide:

- **workspace_url**: https://adb-xxxxxxxxxxx.azuredatabricks.net/
- **account_id**: your databricks account id  (You can find it in the URL when you are in the Account Admin Console: https://accounts.azuredatabricks.net/?account_id=<account_id>)
- **account_api_token**: Depending on the keyvault setting: the keyvault secret name or your databricks secret

### Run the Weaver!
This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.
```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.databricks.model import DatabricksSourceMap

#Load config
config = DatabricksSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Mirrored Azure Databricks catalog´s new One Lake Security policies.

https://github.com/user-attachments/assets/4bacb45f-c019-4389-a711-974ffb550884


## :thread: Snowflake specific setup

### Snowflake Configuration
We assume you have an Entra ID integrated Snowflake workspace, i.e. users in Snowflake have the same login e-mail as in Entra ID and Fabric, ideally imported through a SCIM process.
We also assume you already have a mirrored snowflake database in Microsoft Fabric. If not, please follow the steps in [Create a mirrored Snowflake Datawarehouse in Microsoft Fabric](https://learn.microsoft.com/en-us/fabric/mirroring/snowflake-tutorial). You need to enable One Lake Security by opening the Item in the Fabric UI and click on "Manage OneLake data access".


<img width="512" height="282" alt="image" src="https://github.com/user-attachments/assets/2bc19234-7fbf-4c42-945d-6e215286e97a" />


For the Snowflake setup the Service Principal is required to have User.Read.All permissions for the Graph API to look up the Entra ID object id for each user.

To allow Policy Weaver to read the Snowflake metadata and access policies, you need to create a Snowflake user and role and assign the following privileges. Follow the following steps:
1. Create a new technical user in Snowflake, e.g. with the name POLICYWEAVER. (Optionally, but recommended: setup key-pair authentication for this user with an encrypted key as described [here](https://docs.snowflake.com/en/user-guide/key-pair-auth))
1. Create a new role e.g. ACCOUNT_USAGE and assign the following privileges to this role:
   - IMPORTED PRIVILEGES on the SNOWFLAKE database
   - USAGE on the WAREHOUSE you want to use to run the queries (e.g. COMPUTE_WH)
   - Assign the ACCOUNT_USAGE role to the POLICYWEAVER user

You can use the following SQL statements. Replace the role, user and warehouse names as required.
```sql
CREATE ROLE "ACCOUNT_USAGE";
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE ACCOUNT_USAGE;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE ACCOUNT_USAGE;
GRANT ROLE ACCOUNT_USAGE to USER "POLICYWEAVER";
```

### Update your Configuration file
Download this [config.yaml](./config.yaml) file template and update it based on your environment.

For Snowflake specifically, you will need to provide:

- **account_name**: your snowflake account name (e.g. KWADKA-AK8207) **OR** the secret name in the keyvault if you use keyvault
- **user_name**: the snowflake user name you created for Policy Weaver (e.g. POLICYWEAVER)  **OR** the secret name in the keyvault if you use keyvault
- **private_key_file**: the path to your private key file if you are using key-pair authentication (e.g. ./builtin/rsa_policyweaver_key.p8)
- **password**: the password of the snowflake user if you are using password authentication **OR** the passphrase of your private key if you are using key-pair authentication **OR** the secret name in the keyvault if you use keyvault
- **warehouse**: the snowflake warehouse you want to use to run the queries (e.g. COMPUTE_WH)


### Run the Weaver!
This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.
```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.snowflake.model import SnowflakeSourceMap

#Load config
config = SnowflakeSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Mirrored Snowflake Warehouse´s new One Lake Security policies.


https://github.com/user-attachments/assets/4de93aa3-e6c2-4c5b-b220-b30f6bfafd2f



## :raising_hand: Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## :scroll: License

This project is licensed under the MIT License - see the LICENSE file for details.

## :shield: Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
