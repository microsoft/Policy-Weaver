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
  <a href="https://badgen.net/pypi/dm/policy-weaver" target="_blank">
    <img src="https://badgen.net/pypi/dm/policy-weaver" alt="Monthly Downloads">
</a>
</a>
  <a href="https://badge.socket.dev/pypi/package/policy-weaver?artifact_id=tar-gz" target="_blank">
    <img src="https://badge.socket.dev/pypi/package/policy-weaver?artifact_id=tar-gz" alt="Socket Badge">
</a>
</p>

---

# Policy Weaver: synchronizes data access policies across platforms

A Python-based accelerator designed to automate the synchronization of security policies from different source catalogs with [OneLake Security](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles) roles. While mirroring is only synchronizing the data, **Policy Weaver** is adding the missing piece which is mirroring data access policies to ensure consistent security across data platforms.


## :rocket: Features
- **Microsoft Fabric Support**: Direct integration with Fabric Mirrored Databases/Catalogs and OneLake Security.
- **Runs anywhere**: It can be run within Fabric Notebook or from anywhere with a Python runtime.
- **Effective Policies**: Resolves effective read privileges automatically, traversing nested groups and roles as required.
- **Pluggable Framework**: Supports Azure Databricks, Snowflake, and Azure Data Lake Storage Gen2 policies, with more connectors planned.
- **Secure**: Can use Azure Key Vault to securely manage sensitive information like Service Principal credentials and API tokens.


## Table of Contents
- [Installation](#hammer_and_wrench-installation)
- [Getting Started](#rocket-getting-started)
  - [General Prerequisites](#clipboard-general-prerequisites)
  - [Databricks specific setup](#thread-databricks-specific-setup)
  - [Snowflake specific setup](#thread-snowflake-specific-setup)
  - [ADLS Gen2 specific setup](#thread-adls-gen2-specific-setup)
- [Config File values](#books-config-file-values)
- [Column Level Security](#books-column-level-security)
- [Row Level Security](#books-row-level-security)
- [Feedback](#raising_hand-feedback)


## :hammer_and_wrench: Installation
Make sure your Python version is greater or equal than 3.11. Then, install the library:
```bash
$ pip install policy-weaver
```

# :rocket: Getting Started

Follow the General Prerequisites and Installation steps below [here](#clipboard-general-prerequisites). Then, depending on your source catalog, follow the specific setup instructions for [Databricks](#thread-databricks-specific-setup), [Snowflake](#thread-snowflake-specific-setup), or [ADLS Gen2](#thread-adls-gen2-specific-setup).
If you run into any issues, wish for new features or let us know that you like the accelerator, let us know via our feedback form [https://aka.ms/pwfeedback](https://aka.ms/pwfeedback)

## :clipboard: General Prerequisites
Before installing and running this solution, ensure you have:
- **Azure [Service Principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)** with the following [Microsoft Graph API permissions](https://learn.microsoft.com/en-us/graph/permissions-reference) (*This is not mandatory in every case but recommended, please check the specific source catalog requirements and limitations*):
  - `User.Read.All` as application permissions
- [A client secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-3-create-a-new-client-secret) for the Service Principal
- Added the Service Principal as [Admin](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces) on the Fabric Workspace containing the mirrored database/catalog.
- The Service Principal needs to be able to call public Fabric REST APIs. This is configured in the tenant settings via the following setting [service-principals-can-call-fabric-public-apis]( https://learn.microsoft.com/en-us/fabric/admin/service-admin-portal-developer#service-principals-can-call-fabric-public-apis)

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

In general, you should fill the config file as described here: [Config File values](#books-config-file-values).

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

In general, you should fill the config file as described here: [Config File values](#books-config-file-values).

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


## :thread: ADLS Gen2 specific setup

> :warning: **Beta** — The ADLS Gen2 plugin is currently in **beta**. Features and configuration may change in future releases. Please report any issues via our [feedback form](https://aka.ms/pwfeedback).

### Azure Data Lake Storage Gen2 Configuration
Policy Weaver can read POSIX ACLs from an Azure Data Lake Storage Gen2 account with **Hierarchical Namespace (HNS)** enabled and map them to OneLake Security roles in Microsoft Fabric.

The ADLS Gen2 plugin scans containers and directories, parses the POSIX ACL entries for named users and groups, and produces role-based or table-based permission scopes. Each Entra security group with read access becomes a Fabric data access role whose display name matches the group name.

#### Prerequisites
- An **ADLS Gen2** storage account with **Hierarchical Namespace enabled** (required for POSIX ACLs).
- A **Lakehouse** or **Mirrored Database** in Microsoft Fabric with tables whose schema/table layout corresponds to your ADLS folder structure. Enable OneLake data access by opening the item in the Fabric UI and clicking "Manage OneLake data access".
- The **Service Principal** used by Policy Weaver requires:
  - **Storage Blob Data Reader** (or higher) on the ADLS Gen2 storage account — to read directory ACLs.
  - **Admin** on the Fabric workspace containing the target lakehouse.
  - Microsoft Graph API application permissions:
    - `Group.Read.All` — to resolve Entra group display names for role naming.
    - `Directory.Read.All` — to look up directory objects by Object ID.
  - Admin consent must be granted for these Graph permissions. Use the Azure Portal or:
    ```bash
    az ad app permission admin-consent --id <app-client-id>
    ```
    If admin-consent does not create the app-role assignments, grant them directly:
    ```bash
    az rest --method POST \
      --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-object-id>/appRoleAssignments" \
      --body @role_grant.json
    ```

#### How it works
1. **Scan** — The plugin recursively walks the ADLS container(s), collecting POSIX ACL entries for every directory and file.
2. **Extract** — Named user and group ACL entries with read permission are normalised into grants.
3. **Resolve** — Each principal's Object ID is resolved via Microsoft Graph to obtain the Entra group (or user) display name.
4. **Map** — Grants are expanded to include all discovered sub-directories, parent-only paths are pruned (only leaf/table-level paths remain), and the result is mapped to role-based or table-based Fabric policies.
5. **Sync** — Policies are pushed to the Fabric Data Access Roles API.

#### Path mapping
ADLS paths are mapped to Fabric `/Tables/<schema>/<table>` paths as follows:

| ADLS path | Fabric path | Description |
|-----------|-------------|-------------|
| `/` (root) | `*` | Wildcard — access to everything |
| `sales` | `/Tables/sales` | Schema-level access |
| `sales/reports` | `/Tables/sales/reports` | Table-level access |

When a principal has access to a parent directory, the plugin automatically expands the scope to include **all discovered sub-directories**. If a parent directory has children in the expanded set, the parent is pruned so that only leaf-level (table-level) paths appear in the final policy. A root-level grant (`/`) is simplified to the `*` wildcard.

#### Update your Configuration file
Create a YAML configuration file (e.g. `configadls.yaml`) with the following structure:

```yaml
keyvault:
  use_key_vault: false
  name: notapplicable
  authentication_method: notapplicable
fabric:
  mirror_id: <lakehouse-or-mirror-item-id>
  mirror_name: <item-name>
  workspace_id: <fabric-workspace-id>
  tenant_id: <entra-tenant-id>
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
service_principal:
  client_id: <sp-client-id>
  client_secret: <sp-client-secret>
  tenant_id: <entra-tenant-id>
source:
  name: <the name of the container>
type: ADLS_GEN2
adls:
  account_url: https://<storage-account>.dfs.core.windows.net/
  max_depth: -1                     # optional — -1 for unlimited depth
```

For ADLS Gen2 specifically, you will need to provide:

- **source.name**: <the name of the container>
- **account_url**: The ADLS Gen2 account URL, e.g. `https://mystorageaccount.dfs.core.windows.net/`
- **max_depth** *(optional)*: Maximum directory recursion depth. `-1` means unlimited (default: `-1`).

#### Run the Weaver!
This is all the code you need. Just make sure Policy Weaver can access your YAML configuration file.
```python
# import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.adls.model import AdlsSourceMap

# Load config
config = AdlsSourceMap.from_yaml("path_to_your_configadls.yaml")

# Run the PolicyWeaver
await WeaverAgent.run(config)
```

All done! You can now check your Microsoft Fabric Lakehouse's new OneLake Security policies.


## :books: Config File values

Here ´s how the config.yaml should be adjusted to your environment.

- keyvault:
  - use_key_vault: true/false (true if you want to use keyvault to store secrets, false if you want to store secrets directly in the config file)
  - name: your keyvault name (only required if use_key_vault is true)
  - authentication_method: azure_cli / fabric_notebook (only required if use_key_vault is true) :right_arrow: use fabric_notebook if you run it in a fabric notebook, otherwise use azure_cli and login with `az login` before running the weaver

- fabric:
    - mirror_id: the item id of the mirrored catalog/database/warehouse (you can find it in the URL when you open the workload item in the Fabric UI)
    - mirror_name: the name of the item in Fabric
    - workspace_id: your fabric workspace id (you can find it in the URL when you are in the Fabric workspace)
    - tenant_id: your fabric tenant id (you can find it in the URL "help" -> "about Fabric" section of the Fabric UI)
    - fabric_role_suffix: suffix for the fabric roles created by Policy Weaver (default: PW)
    - delete_default_reader_role: true/false (if true, the DefaultReader role created by Fabric will be deleted, if false it will be kept, default: true)
    - policy_mapping: table_based / role_based (table_based: create one role per table, role_based: create one role per role/group, default: table_based)
- constraints:
    - columns: (optional, if not set, no column level security will be applied, see below for details [Column Level Security](#books-column-level-security))
      - columnlevelsecurity: true/false (if true, column level security will be applied at best effort. Default: false)
      - fallback: grant/deny (if a not supported column mask is found, the fallback will be applied. Default: deny)
    - rows: (optional, if not set, no row level security will be applied, see below for details [Row Level Security](#books-row-level-security))
      - rowlevelsecurity: true/false (if true, row level security will be applied at best effort. Default: false)
      - fallback: grant/deny (if a not supported row mask is found, the fallback will be applied. Default: deny)

- service_principal:
  - client_id: the client id of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault
  - client_secret: the client secret of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault
  - tenant_id: the tenant id of the service principal mentioned under general prerequisites **OR** the corresponding secret name in the keyvault if you use keyvault

- source:
  - name of the unity catalog or snowflake database
  - schemas: list of schemas to include. If not set, all schemas are included. For each schema you can give a list of tables which should be included. If not set all tables are included (see examples below)

- type: either 'UNITY_CATALOG' for databricks, 'SNOWFLAKE' for snowflake, or 'ADLS_GEN2' for Azure Data Lake Storage Gen2

Here is an example config.yaml **NOT** using keyvault:

```yaml
keyvault:
  use_key_vault: false
  name: notapplicable
  authentication_method: notapplicable
fabric:
  mirror_id: 845464654646adfasdf45567
  mirror_name: salescatalog
  workspace_id: 9d556498489465asdf7c
  tenant_id: 3494545asdfs7e2885
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
service_principal:
  client_id: 89ac5a4sd894as9df4sad89f
  client_secret: 1234556dsad4848129
  tenant_id: 3494545asdfs7e2885
source:
  name: dbxsalescatalog
  schemas: <---- optional, if not provided all schemas will be scanned
  - name: analystschema
    tables: <---- optional, if not provided all tables will be scanned
    - subsubanalysttable
type: UNITY_CATALOG
databricks:
  workspace_url: https://adb-6a5s4df9sd4fasdf.0.azuredatabricks.net/
  account_id: 085a54s65a4sfa6565asdff
  account_api_token: 74adsf84ad8f4a8sd4f8asdf
snowflake:
  account_name: KAIJOIWA-DUAK8207
  user_name: POLICYWEAVER
  private_key_file: rsa_key.p8
  password: ODFJo12io1212
  warehouse: COMPUTE_WH
```

Here is an example config.yaml **using** keyvault. 

:clipboard: Note that in this case, the user running the weaver needs to have access to the keyvault and the secrets.

```yaml
keyvault:
  use_key_vault: true
  name: policyweaver20250912
  authentication_method: fabric_notebook
fabric:
  mirror_id: 845464654646adfasdf45567
  mirror_name: SFDEMODATA
  workspace_id: 9d556498489465asdf7c
  tenant_id: 3494545asdfs7e2885
  fabric_role_suffix: PW
  delete_default_reader_role: true
  policy_mapping: role_based
constraints:
  columns:
    columnlevelsecurity: true
    fallback: deny
  rows:
    rowlevelsecurity: true
    fallback: deny
service_principal:
  client_id: kv-service-principal-client-id
  client_secret: kv-service-principal-client-secret
  tenant_id: kv-service-principal-tenant-id
source:
  name: SFDEMODATA
  schemas: <---- optional, if not provided all schemas will be scanned
  - name: analystschema
    tables: <---- optional, if not provided all tables will be scanned
    - subsubanalysttable
type: SNOWFLAKE
databricks:
  workspace_url: https://adb-1441751476278720.0.azuredatabricks.net/
  account_id: 085f281e-a7ef-4faa-9063-325e1db8e45f
  account_api_token: kv-databricks-account-api-token
snowflake:
  account_name: kv-sfaccountname
  user_name: kv-sfusername
  private_key_file: rsa_key.p8
  password: kv-sfpassword
  warehouse: COMPUTE_WH
```


## :books: Column Level Security

Column level security is an optional feature that can be enabled in the config file. If enabled, Policy Weaver will try to apply column level security at best effort and fallback to the configured fallback if a not supported column mask is found.

:warning: NOTE: Column level security is only enabled if the config `policy_mapping` is set to `role_based`. In the case of table_based mapping there would be an unforeseeable high number of roles created in Fabric. That´s why it can only be used in role_based mapping.

Databricks and Snowflake support column level security by column mask policies. However, OneLake Security currently only supports column level security by denying access to specific columns.

Given the biggest use case for column mask policies is to hide the whole column, this still aligns. However, if you have a column mask policy that is not supported by Policy Weaver, you can configure the fallback to either grant or deny access to this column by default.

Supported column mask policies:
- Databricks:
  - Allow only a specific group to see the real value. I.e. the function looks like `CASE WHEN is_account_group_member('HumanResourceDept') THEN ssn ELSE '<arbitrary_value>' END`
  - Allow everyone except a specific group to see the real value.  I.e. the function looks like `CASE WHEN is_account_group_member('HumanResourceDept') THEN '<arbitrary_value>' ELSE ssn END`
- Snowflake:
  - Allow only a specific role to see the real value. I.e. the function looks like `CASE WHEN CURRENT_ROLE() IN ('HR_ROLE') THEN ssn ELSE '<arbitrary_value>' END`
  - Allow everyone except a specific role to see the real value.  I.e. the function looks like `CASE WHEN CURRENT_ROLE() IN ('HR_ROLE') THEN '<arbitrary_value>' ELSE ssn END`

If for a specific role all columns of a table are denied, the whole table is denied to this role and will not show up in the Fabric for this role.
:warning: NOTE: Our recommendation is to set the fallback to deny to avoid unintentional data exposure. If you identify a scenaro where there is a data exposure risk, please give us feedback and we´ll try to fix it asap. Note though that this solution is provided as-is without any warranties.

## :books: Row Level Security

Row level security is an optional feature that can be enabled in the config file. If enabled, Policy Weaver will try to apply row level security at best effort and fallback to the configured fallback if a not supported row access policy is found.


:warning: NOTE: Row level security is only enabled if the config `policy_mapping` is set to `role_based`. In the case of table_based mapping there would be an unforeseeable high number of roles created in Fabric. That´s why it can only be used in role_based mapping.


Databricks and Snowflake support various row level security variations. We currently only support simple row access policies defined on top of a table. OneLake Security sets row level security filters not on a table scope but a "table + role"-scope. For many use cases we can map the simple row access policies to this "table + role"-scope.


If you have a row access policy that is not supported by Policy Weaver, you can configure the fallback to either grant or deny access to the whole table by default. This also includes unsupported policies like aggregation, join or projection policies in Snowflake.
:warning: NOTE: Our recommendation is to set the fallback to deny to avoid unintentional data exposure. If you identify a scenaro where there is a data exposure risk, please give us feedback and we´ll try to fix it asap. Note though that this solution is provided as-is without any warranties.


Supported row access policies:
- Databricks:
  - Specify a filter for a specific group and a default for the rest in the form of: `IF(IS_ACCOUNT_GROUP_MEMBER('admin'), true, region='US');` 
  - Based on group membership allow access to certain rows via a CASE statement in the form of: `CASE WHEN IS_ACCOUNT_GROUP_MEMBER('subanalystgroup') THEN true WHEN IS_ACCOUNT_GROUP_MEMBER('analystgroup') THEN Id = 'T001' ELSE false END`


- Snowflake:
  - Allow only specific groups to see the values in the form of: `current_role() in ('SENSITIVE')`
  - Based on group membership allow access to certain rows via a CASE statement in the form of: `CASE WHEN current_role() in ('SENSITIVE') THEN true  WHEN current_role() in ('COUNTRY') THEN Id = 'T001' ELSE false END`


If you see demand for more (simple) row access policies which are not supported, please give us feedback and we´ll try to add them.


If for a specific role all columns of a table are denied, the whole table is denied to this role and will not show up in the Fabric for this role.


## :raising_hand: Feedback

If you run into any issues, wish for new features or let us know that you like the accelerator, let us know via our feedback form [https://aka.ms/pwfeedback](https://aka.ms/pwfeedback)


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
