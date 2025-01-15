import asyncio

from policyweaver.policyweaver import Weaver
from policyweaver.models.databricksmodel import DatabricksSourceMap

#Load config from the default path (./settings.yaml)
config = DatabricksSourceMap.from_yaml()
asyncio.run(Weaver.run(config))