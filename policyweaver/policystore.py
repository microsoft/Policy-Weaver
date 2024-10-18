from pydantic import BaseModel
from enum import Enum

class FabricAccessType(Enum):
    """
    FabricAccessType is an enumeration that defines different types of access permissions 
    for a fabric. The available access types are:
    - READ: Represents read-only access.
    - WRITE: Represents write access.
    """

    READ = "Read"
    WRITE = "Write"

class EntraMemberType(Enum):
    """
    EntraMemberType is an enumeration that represents different types of members in the Entra system.
    Attributes:
        GROUP (str): Represents a group member type.
        USER (str): Represents a user member type.
    """

    GROUP = "Group"
    USER = "User"

class FabricItem(BaseModel):
    """
    A class representing an item in the fabric.
    Attributes:
        path (str): The path associated with the fabric item.
    """

    path: str

class FabricWorkspace(BaseModel):
    """
    FabricWorkspace is a model representing a workspace in the fabric system.
    Attributes:
        tenantid (str): The tenant ID associated with the workspace.
        id (str): The unique identifier for the workspace.
        name (str): The name of the workspace.
        items (list[FabricItem]): A list of FabricItem objects associated with the workspace.
    """

    tenantid: str
    id: str
    name: str
    items: list[FabricItem]

class PolicyMember(BaseModel):
    """
    Represents a member of a policy.
    Attributes:
        name (str): The name of the policy member.
        objectid (str): The unique identifier of the policy member.
        type (EntraMemberType): The type of the policy member.
    """

    name: str
    objectid: str
    type: EntraMemberType

class AccessPolicy(BaseModel):
    """
    AccessPolicy class represents an access policy within a workspace.
    Attributes:
        id (str): Unique identifier for the access policy.
        name (str): Name of the access policy.
        workspace (FabricWorkspace): The workspace to which the access policy belongs.
        accesstype (FabricAccessType): Type of access granted by the policy.
        members (list[PolicyMember]): List of members associated with the access policy.
    """

    id: str
    name: str
    workspace: FabricWorkspace
    accesstype: FabricAccessType
    members: list[PolicyMember]
