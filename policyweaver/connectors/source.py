from typing import List, Dict, Optional
from abc import ABC, abstractmethod

class PolicySource(ABC):
    @abstractmethod
    def connect(self):
        pass

    @abstractmethod
    def get_tables(self) -> List:
        pass

    @abstractmethod
    def get_policies(self, table: str) -> List:
        pass

class PolicyService:
    def __init__(self, source: PolicySource) -> None:
        self.source = PolicySource
    
    def get_access_policies(self, table: str) -> List:
        return self.source.get_policies(table=table)
