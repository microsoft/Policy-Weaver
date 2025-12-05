import asyncio
import logging

from policyweaver.weaver import WeaverAgent
from policyweaver.plugins.databricks.model import DatabricksSourceMap

#Load config
config = DatabricksSourceMap.from_yaml("configdbx.yaml")

#configure logging for the client (DEBUG for verbose output)
log_level = logging.DEBUG
logger = logging.getLogger("POLICY_WEAVER")
logger.setLevel(log_level)

console_handler = logging.StreamHandler()
console_handler.setLevel(log_level) 

formatter = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

#run weaver
asyncio.run(WeaverAgent.run(config))