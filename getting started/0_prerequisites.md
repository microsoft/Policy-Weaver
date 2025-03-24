## Disclaimer: The following prerequisites apply for Policy Weaver for Azure Databricks and Microsoft Fabric

PolicyWeaver is available on [PyPi](https://pypi.org/project/policy-weaver/) and can be installed via `pip install policy-weaver`.

### Create an Azure Service Principal account
Before we start using PolicyWeaver, it is necessary to create an Azure service principal on portal.azure.com to authenticate to both systems, and schemas/tables and give the following permissions for the source and target system:

1. For Azure Databricks: xx
2. For Microsoft Fabric: xx

### Create in Microsoft Fabric a Mirrored Azure Databricks Catalog item
To access Azure Databricks tables in Microsoft Fabric, a new item in Fabric called [Mirrored Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks), comes in handy. The metastore of Azure Databricks gets replicated in Fabric, while the delta parquet tables are being virtualized (shortcut) into Fabric.

------SYDNE TO CONTINUE TO UPDATE--------

### Create a yaml configuration file
Additionally, it is required to create a yaml configuration file to map the source system details and the target Fabric environment.

You can use VS Code or any other environment to create a yaml file with the following content:

```yml
fabric:
  lakehouse_name: mirrored_schemas
  workspace_id: <your_Fabric_workspace_id>
service_principal:
  client_id: <sp_client_id>
  client_secret: <sp_client_secret>
  tenant_id: <sp_tenant_id>
source:
  name: <source_warehouse_catalog>
  schemas:
  - name: <schema_1>
    tables:
    - <table_1>
type: UNITY_CATALOG
workspace_url: <databricks_workspace_url>
```

With PolicyWeaver installed and the configuration file ready, we start by reading the configuration file and running the Weaver.

```python
from policyweaver.policyweaver import Weaver
from policyweaver.models.databricksmodel import DatabricksSourceMap

config = DatabricksSourceMap.from_yaml('path_to_yaml_config_file')

await Weaver.run(config)
```