from dataclasses import dataclass
from enum import Enum

class FabricAccessType(Enum):
    READ = "Read"
    WRITE = "Write"

class EntraMemberType(Enum):
    GROUP = "Group"
    USER = "User"

@dataclass
class FabricItem:
    path: str

@dataclass
class FabricWorkspace:
    tenantid: str
    id: str
    name: str
    items: list[FabricItem]

@dataclass
class PolicyMember:
    name: str
    objectid: str
    type: EntraMemberType

@dataclass
class AccessPolicy:
    id: str
    name: str
    workspace: FabricWorkspace
    accesstype: FabricAccessType
    members: list[PolicyMember]
