import asyncio
import logging

from policyweaver.plugins.snowflake.model import SnowflakeSourceMap
from policyweaver.weaver import WeaverAgent

#Load config
config = SnowflakeSourceMap.from_yaml("config.yaml")

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