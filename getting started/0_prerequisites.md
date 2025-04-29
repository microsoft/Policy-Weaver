## Disclaimer: The following prerequisites apply for Policy Weaver for Azure Databricks and Microsoft Fabric

PolicyWeaver is available on [PyPi](https://pypi.org/project/policy-weaver/) and can be installed via `pip install policy-weaver`.

### Create a Microsoft Entra Application and Service Principal account
Before we start using PolicyWeaver, it is necessary to create an Entra Application in Azure for identity management. When you register a new application in Microsoft Entra ID, a service principal is automatically created for the app registration and it is the app's identity in the Microsoft Entra tenant. You can restrict access to resources like Azure Databricks and Fabric by the roles that you assign to the service principal. Follow the steps [here](https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal) to register an application in Microsoft Entra ID and create a service principal account. 


1. For Microsoft Fabric (you have to have admin rights): 
    - create a Fabric workspace identity as stated [here under step 1](https://learn.microsoft.com/en-us/fabric/security/workspace-identity-authenticate#step-1-create-the-workspace-identity)
    - the service principal needs to be a workspace admin in Fabric workspace
    - enable service principal authentication in Fabric as documented [here](https://learn.microsoft.com/en-us/fabric/admin/enable-service-principal-admin-apis)
    - give the service principal access to your Fabric workspace and [assign the "Contributor" role](https://learn.microsoft.com/en-us/fabric/fundamentals/give-access-workspaces)

  2. For Azure Databricks (you have to have admin rights):
      - ensure Unity Catalog is enabled on your Azure Databricks workspace
      -  [enable external data access](https://learn.microsoft.com/en-us/azure/databricks/external-access/admin#enable-external-data-access-on-the-metastore) on the metastore
      - grant the service principal "use external schema" and "manage" privilege

### Create a Mirrored Azure Databricks Catalog item in Microsoft Fabric
To access Azure Databricks tables in Microsoft Fabric, a new item in Fabric called [Mirrored Azure Databricks Catalog](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks) which is currently in public preview, comes in handy. The metastore of Azure Databricks gets replicated in Fabric, while the delta parquet tables are being virtualized (shortcut) from Azure Databricks into Fabric. You can find the tutorial how to create the Mirroed Azure Databricks Catalog item in Fabric and how to select tables [here](https://learn.microsoft.com/en-us/fabric/database/mirrored-database/azure-databricks-tutorial#create-a-mirrored-database-from-azure-databricks). Have in mind, that you can only select schemas and tables that you have access to.



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