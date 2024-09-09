from policyweaver.connectors.source import *

class NullConnector(PolicySource):
    def __init__(self):
        return
    
    def open(self):
        return
    
    def close(self):
        return
    
    def validate(self):
        True
    
    def get_policies(self) -> list:
        return []