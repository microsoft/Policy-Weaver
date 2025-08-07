## Disclaimer: The following prerequisites apply for Policy Weaver for Azure Databricks and Microsoft Fabric

PolicyWeaver is available on [PyPi](https://pypi.org/project/policy-weaver/) and can be installed via `pip install policy-weaver`.

### Create an Azure Service Principal account
Before we start using PolicyWeaver, it is necessary to create an Azure service principal on the [Azure Portal](https://portal.azure.com/) to authenticate to both Microsoft Fabric and Azure Databricks. 

Ensure the service principal has the following permissions in Azure Databricks and Microsoft Fabric. Attention: You need to have admin rights.

1. Azure Databricks
    -  Under workspace settings > Identity & Access > Manage Service Principals > add your Azure Service Principal 
        - once added, click on the Service Principal name and switch to the "Permissions" tab to grant "Service Principal:Manager" role
        - switch to the "Secret" tab to create an OAuth secret for the config.yaml file later (note it down)
    - Under account admin console > User Management > change tab to Service Principals > add your Azure Service Principal
        - switch to "Roles" tab and toggle to activate the "Account admin" role 
        - switch to the "Permissions" tab and ensure your Service Principal has the "Service Principal:Manager" permission
2. Microsoft Fabric

### Create a Mirrored Azure Databricks Catalog item in Microsoft Fabric
To access Azure Databricks tables in Microsoft Fabric, a new item in Fabric called [Mirrored Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks) which is currently in public preview, comes in handy. The metastore of Azure Databricks gets replicated in Fabric, while the delta parquet tables are being virtualized (shortcut) from Azure Databricks into Fabric. You can find the tutorial how to create the Mirroed Azure Databricks Catalog item in Fabric and how to select tables [here](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks-tutorial#create-a-mirrored-database-from-azure-databricks). Have in mind, that you can only select tables that you have access to.


### Create a Microsoft Fabric Lakehouse
As stated in README, we are using the Microsoft Fabric OneLake access roles, currently in Public Preview. Data access role security DOES NOT YET apply to the Mirrored Azure Databricks Catalog item in Fabric. Therefore, we create a Lakehouse and will shortcut the tables from Mirrored Azure Databricks Catalog to a Fabric Lakehouse to synchronize access policies between Azure Databricks and Fabric. [Here](https://learn.microsoft.com/en-us/fabric/data-engineering/create-lakehouse) is stated how to create a Fabric Lakehouse.


### Create a yaml configuration file
Additionally, it is required to create a yaml configuration file to map the source system details and the target Fabric environment.

You can use VS Code or any other tool to create a yaml file with the following content below, ensure you replace the information ind "< >" with your individual credentials. Save this on your local computer for now. 


```yml
keyvault:
  use_key_vault: <true if you use a key vault and secret names, false if you provide the secrets>
  name: <nameofkeyvault>
  authentication_method: <authentication method: currently possible: azure_cli or fabric_notebook>
fabric:
  mirror_id: <your fabric mirrored item id>
  mirror_name: <your fabric mirrored item name>
  workspace_id: <your fabric workspace id>
  tenant_id: <your fabric tenant id>
  fabric_role_suffix: PWPolicy
  delete_default_reader_role: true
service_principal:
  client_id: <Depending on the keyvault setting: the keyvault secret name or your azure SP client id>
  client_secret: <Depending on the keyvault setting: the keyvault secret name or your azure SP secret>
  tenant_id: <Depending on the keyvault setting: the keyvault secret name or your azure tenant id again>
source:
  name: <your databricks catalog name as named in Azure Databricks>
type: UNITY_CATALOG
databricks:
  workspace_url: https://adb-xxxxxxxxxxx.azuredatabricks.net/
  account_id: <your databricks account id>
  account_api_token: <Depending on the keyvault setting: the keyvault secret name or your databricks secret>
```