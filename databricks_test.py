import asyncio
import logging
from policyweaver.policyweaver import Weaver
from policyweaver.models.databricksmodel import DatabricksSourceMap

#Load config from the default path (./settings.yaml)
config = DatabricksSourceMap.from_yaml("./config.yaml")

#configure logging for the client
log_level = logging.DEBUG

logger = logging.getLogger("POLICY_WEAVER")
logger.setLevel(log_level)

console_handler = logging.StreamHandler()
console_handler.setLevel(log_level) 

formatter = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

#run weaver
asyncio.run(Weaver.run(config))