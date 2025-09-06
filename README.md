  <p align="center">
  <img src="./policyweaver.png" alt="Policy Weaver icon" width="200"/>
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

A Python-based accelerator designed to automate the synchronization of security policies from different source catalogs with [OneLake Security](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles) roles. This is required when using OneLake mirroring to ensure consistent security across data platforms.


## :rocket: Features
- **Microsoft Fabric Support**: Direct integration with Fabric Mirrored Databases and OneLake Security.
- **Runs anywhere**: It can be run within Fabric Notebook or from anywhere with a Python runtime.
- **Effective Policies**: Resolves effective read privileges automatically, traversing nested groups and roles as required.
- **Pluggable Framework**: Supports Azure Databricks and Snowflake policies, with more connectors planned.
- **Secure**: Can use Azure Key Vault to securely manage sensitive information like Service Principal credentials and API tokens.

> :pushpin: **Note:** Row-level and column-level security extraction will be implemented in the next version, once these features become available in OneLake Security.

## :clipboard: Prerequisites
Before installing and running this solution, ensure you have:
- **Azure [Service Principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal)** with the following [Microsoft Graph API permissions](https://learn.microsoft.com/en-us/graph/permissions-reference):
  - `Application.Read.All`
  - `User.Read`
  - `User.Read.All`
  - `Directory.Read.All`
- [A client secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-3-create-a-new-client-secret) for the Service Principal
- Added the Service Principal as [Admin](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces) on the Fabric Workspace cpontaining the mirror database.

> :pushpin: **Note:** Every source catalog has additional pre-requisites

## :hammer_and_wrench: Installation
Make sure your Python version is greater or equal than 3.11. Then, install the library:
```bash
$ pip install policy-weaver
```


## :thread: Databricks Example

### Azure Databricks Configuration
1. Create a [Mirror Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/mirroring/azure-databricks-tutorial) in a Microsoft Fabric Workspace.
1. Account Admin Console :arrow_right: User Management :arrow_right: Add your Azure Service Principal. 
    1. **Role**: "Account admin"
    1. **Permission**: "Service Principal:Manager"
1. Workspace Settings :arrow_right: Identity & Access :arrow_right: Manage Service Principals :arrow_right: Add your Azure Service Principal.
    1. **Permission**: "Service Principal:Manager" permission. 
    1. **Generate** an OAuth secret for your config.yaml file.

### Update your Configuration file
Download this [config.yaml](./config.yaml) file template and update it based on your environment.

For Databricks specifically, you will need to provide:

- **workspace_url**: https://adb-xxxxxxxxxxx.azuredatabricks.net/
- **account_id**: your databricks account id
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

All done! You can now check your Microsoft Fabric Mirrored Azure Databricks catalog new policies.

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