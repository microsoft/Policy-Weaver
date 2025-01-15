import asyncio

from policyweaver.auth import ServicePrincipal
from policyweaver.models.common import SourceMap
from policyweaver.policyweaver import Weaver
from policyweaver.sources.databricksclient import DatabricksPolicyWeaver
from policyweaver.models.databricksmodel import DatabricksSourceMap

from policyweaver.models.common import (
    SourceMap,
    PolicyWeaverConnectorType,
    )
    
async def weaver_run(config) -> None:
    service_principal = ServicePrincipal(
            tenant_id=config.service_principal.tenant_id,
            client_id=config.service_principal.client_id,
            client_secret=config.service_principal.client_secret
        )
    
    print("Policy Weaver Sync started...")
    if config.type == PolicyWeaverConnectorType.UNITY_CATALOG:
        src = DatabricksPolicyWeaver(config, service_principal)
    
    print(f"Running Policy Export for {config.type}: {config.source.name}...")
    policy_export = src.map_policy()
    
    weaver = Weaver(config, service_principal)
    await weaver.run(policy_export)
    print("Policy Weaver Sync complete!")


#Load config from the default path (./settings.yaml)
config = DatabricksSourceMap.from_yaml()
asyncio.run(weaver_run(config))