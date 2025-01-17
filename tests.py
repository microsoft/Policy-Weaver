from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import List, Dict
import json
import re

from policyweaver.policyweaver import Weaver
from policyweaver.models.databricksmodel import DatabricksSourceMap

from policyweaver.auth import ServicePrincipal
from policyweaver.support.fabricapiclient import FabricAPI
from policyweaver.support.microsoftgraphclient import MicrosoftGraphClient
from policyweaver.sources.databricksclient import DatabricksPolicyWeaver
from policyweaver.models.fabricmodel import (
    DataAccessPolicy,
    PolicyDecisionRule,
    PolicyEffectType,
    PolicyPermissionScope,
    PolicyAttributeType,
    PolicyMembers,
    EntraMember,
    FabricMemberObjectType,
    FabricPolicyAccessType,
)
from policyweaver.models.common import (
    PolicyExport,
    PermissionType,
    PermissionState,
    IamType,
    SourceMap,
    PolicyWeaverError,
    PolicyWeaverConnectorType,
)

config = DatabricksSourceMap.from_yaml()

service_principal = ServicePrincipal(
    tenant_id=config.service_principal.tenant_id,
        client_id=config.service_principal.client_id,
        client_secret=config.service_principal.client_secret)

weaver = Weaver(config, service_principal)

lakehouse_id = weaver.fabric_api.get_lakehouse_id(config.fabric.lakehouse_name)



print(f"lakehouse_id: {lakehouse_id}")

lakehouse_schema = weaver.fabric_api.has_schema(lakehouse_id)

print(f"lakehouse_schema: {lakehouse_schema}")
print("Done")