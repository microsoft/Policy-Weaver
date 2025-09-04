  <p align="center">
  <img src="./policyweaver.png" alt="Policy Weaver icon" width="200"/>
</p>

<p align="center">
    <em>Policy Weaver, synchronizes data access policies across platforms.</em>
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

**Policy Weaver** is a Python-based accelerator designed to automate the synchronization of security policies from different source catalogs with [OneLake Security](https://learn.microsoft.com/en-us/fabric/onelake/security/get-started-data-access-roles). This is required when using OneLake mirroring to ensure consistent security across data platforms.

It currently supports Azure Databricks and Snowflake. Policy Weaver is designed with a pluggable framework, so new connectors can be added to support additional data sources as needed.

Key Features:
- Lightweight Python library that can be run either within Fabric Notebook or from anywhere with a Python runtime.
- Extracts security policies from Databricks via API and maps them to OneLake Security roles.
- Resolves effective read privileges automatically, following Databricks documentation—no manual mapping required.
- Simple configuration and lightweight deployment; can run locally or in a Fabric notebook.
- Syncs changes in Databricks policies to OneLake Security, updating or removing roles as needed.
- Supports catalog, schema, and table-level policies.

Row-level and column-level security extraction will be implemented in the next version, once these features become available in OneLake Security.

----
## Installation
Create and activate virtual environments and then install **Policy Weaver**:
```bash
$ pip install policy-weaver
```

Make sure your Python version is greater or equal than 3.11. If you are running this on a Spark notebook, make sure it uses Spark 3.5 or higher.

---
## Prerequisites

- Create an Azure [Service Principal](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal) account with the following [Microsoft Graph API permissions](https://learn.microsoft.com/en-us/graph/permissions-reference):
  - `Application.Read.All`
  - `User.Read`
  - `User.Read.All`
  - `Directory.Read.All`
- [Create a new client secret](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal#option-3-create-a-new-client-secret) for the Service Principal and note it down.
- Add the Service Principal as [Admin](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces) on the workspace you will be applying Policy Weaver.

---
## Databricks Example

After creating a [Mirror Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/mirroring/azure-databricks-tutorial) in a Microsoft Fabric Workspace, complete these Databricks specific steps:
- In the Account Admin Console, under User Management, add your Azure Service Principal. Make sure it has the "Account admin" role and the "Service Principal:Manager" permission
- In the Workspace Settings > Identity & Access > Manage Service Principals > add your Azure Service Principal, grant it the "Service Principal:Manager" permission, and generate an OAuth secret for the config.yaml file later (note it down)
- Update your [config.yaml](./config.yaml) file based on your environment. 

Sample Code:   
```python
#import the PolicyWeaver library
from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.databricks.model import DatabricksSourceMap

#Load config
config = DatabricksSourceMap.from_yaml("path_to_your_config.yaml")

#run the PolicyWeaver
await WeaverAgent.run(config)
```

---

## Next Steps

Comprehensive information on configuring your YAML file,can be found [here](getting_started/0_prerequisites.md) documentation.

Detailed examples for the following source systems are available:
- [Azure Databricks Unity Catalog](getting_started/0_prerequisites.md)
- BigQuery
- Snowflake

---
## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

----
## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.