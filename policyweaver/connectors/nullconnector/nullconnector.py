from typing import List, Dict
from policyweaver.connectors.source import *

class NullConnector(PolicySource):
    def __init__(self, config:Dict[str, str]):
        self.config = config
    
    def connect(self):
        print("Connected to NULL host...")
    
    def get_tables(self) -> List:
        return [""]
    
    def get_policies(self, table: str) -> List:
        return [""]