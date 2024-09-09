from abc import ABC, abstractmethod

class PolicySource(ABC):
    @abstractmethod
    def open(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def validate(self) -> bool:
        pass

    @abstractmethod
    def get_policies() -> list:
        pass

class PolicyService:
    def __init__(self, source: PolicySource) -> None:
        self.source = PolicySource
    
    def get_access_policies(self) -> list:
        policies = []

        if self.source.validate():
            self.source.open()
            policies = self.source.get_policies()
            self.source.close()

        return policies
