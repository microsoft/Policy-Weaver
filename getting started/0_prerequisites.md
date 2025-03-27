## Disclaimer: The following prerequisites apply for Policy Weaver for Azure Databricks and Microsoft Fabric

PolicyWeaver is available on [PyPi](https://pypi.org/project/policy-weaver/) and can be installed via `pip install policy-weaver`.

### Create an Azure Service Principal account
Before we start using PolicyWeaver, it is necessary to create an Azure service principal on the [Azure Portal](https://portal.azure.com/) to authenticate to both Microsoft Fabric and Azure Databricks. Ensure the service principal has the following permissions for the source (Azure Databricks and target (Microsoft Fabric) system:

1. For Azure Databricks: In the Azure Databricks...
2. For Microsoft Fabric: the service principal needs to be a workspace admin in Fabric workspace

### Create a Mirrored Azure Databricks Catalog item in Microsoft Fabric
To access Azure Databricks tables in Microsoft Fabric, a new item in Fabric called [Mirrored Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks) which is currently in public preview, comes in handy. The metastore of Azure Databricks gets replicated in Fabric, while the delta parquet tables are being virtualized (shortcut) from Azure Databricks into Fabric. You can find the tutorial how to create the Mirroed Azure Databricks Catalog item in Fabric and how to select tables [here](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks-tutorial#create-a-mirrored-database-from-azure-databricks). Have in mind, that you can only select tables that you have access to.


### Create a Microsoft Fabric Lakehouse
As stated in README, we are using the Microsoft Fabric OneLake access roles, currently in Public Preview. Data access role security DOES NOT YET apply to the Mirrored Azure Databricks Catalog item in Fabric. Therefore, we create a Lakehouse and will shortcut the tables from Mirrored Azure Databricks Catalog to a Fabric Lakehouse to synchronize access policies between Azure Databricks and Fabric. [Here](https://learn.microsoft.com/en-us/fabric/data-engineering/create-lakehouse) is stated how to create a Fabric Lakehouse.


### Create a yaml configuration file
Additionally, it is required to create a yaml configuration file to map the source system details and the target Fabric environment.

You can use VS Code or any other tool to create a yaml file with the following content below, ensure you replace the information ind "< >" with your individual credentials. Save this on your local computer for now. 


```yml
fabric:
  lakehouse_name: <lakehouse_name_created_above>
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