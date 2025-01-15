import asyncio

from policyweaver.models.common import SourceMap
from policyweaver.policyweaver import Weaver
from policyweaver.sources.databricksclient import DatabricksPolicyWeaver

from dotenv import load_dotenv 
import os

load_dotenv()

workspace_id=os.getenv('FABRIC_WORKSPACE_ID')
print(f"Workspace: {workspace_id}")

def create_config():
    from policyweaver.models.common import (
    SourceMap,
    Source,
    SourceSchema,
    SourceMapItem,
    ServicePrincipalConfig,
    FabricConfig,
    PolicyWeaverConnectorType,
    )
    return SourceMap(
    type=PolicyWeaverConnectorType.UNITY_CATALOG,
    source=Source(
        name="bluewater_dw",
        schemas=[
            SourceSchema(name="taxi", tables=["nyctaxi_yellow"]),
            SourceSchema(name="wwi"),
        ],
    ),
    service_principal=ServicePrincipalConfig(
        client_id=os.getenv('SERVICE_PRINCIPAL_CLIENT_ID'),
        client_secret=os.getenv('SERVICE_PRINCIPAL_CLIENT_SECRET'),
        tenant_id=os.getenv('SERVICE_PRINCIPAL_TENANT_ID'),
    ),
    fabric=FabricConfig(
        api_token=os.getenv('FABRIC_API_TOKEN'),
        workspace_id=os.getenv('FABRIC_WORKSPACE_ID'),
        lakehouse_name="mirrored",
    ),
    mapped_items=[
        SourceMapItem(
            catalog="bluewater_dw",
            catalog_schema="taxi",
            table="nyctaxi_yellow",
            lakehouse_table_name="nyctaxi_yellow",
            )
        ],
    )
    
async def weaver_run(config: SourceMap, dbx_token, dbx_workspace):
    # Create Databricks Policy
    dbx_policy_weaver = DatabricksPolicyWeaver(workspace=dbx_workspace, token=dbx_token)
    # Extract Databricks Policy
    dbx_policy_export = dbx_policy_weaver.map_policy(config.source)
    # Create Policy Weaver
    weaver = Weaver(config)
    # Run Policy Weaver
    await weaver.run(dbx_policy_export)


asyncio.run(weaver_run(create_config(), os.getenv('DBX_TOKEN'), os.getenv('DBX_WORKSPACE')))
print("Done")
