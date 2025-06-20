from pydantic import Field
from typing import Optional, List, Dict

from policyweaver.core.utility import Utils
from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap
from policyweaver.core.enum import IamType

class DependencyMap(CommonBaseModel):
    """
    Represents a map of dependencies for a specific privilege.
    This is used to track the dependencies of privileges in a structured way.
    Attributes:
        catalog (Optional[str]): The name of the catalog.
        catalog_schema (Optional[str]): The schema within the catalog.
        table (Optional[str]): The name of the table.
        privileges (Optional[List[str]]): A list of privileges associated with this dependency.
        catalog_prerequisites (Optional[bool]): Indicates if catalog prerequisites are required.
        schema_prerequisites (Optional[bool]): Indicates if schema prerequisites are required.
        read_permissions (Optional[bool]): Indicates if read permissions are required.
    The `key` property returns a unique key for the dependency map based on its attributes.
    """
    catalog: Optional[str] = Field(alias="catalog", default=None)
    catalog_schema: Optional[str] = Field(alias="schema", default=None)
    table: Optional[str] = Field(alias="table", default=None)
    privileges: Optional[List[str]] = Field(alias="privileges", default=[])
    catalog_all_cascade: Optional[bool] = Field(alias="catalog_all_cascade", default=False)
    catalog_prerequisites: Optional[bool] = Field(alias="catalog_prerequisites", default=False)
    schema_all_cascade: Optional[bool] = Field(alias="schema_all_cascade", default=False)
    schema_prerequisites: Optional[bool] = Field(alias="schema_prerequisites", default=False)
    read_permissions: Optional[bool] = Field(alias="read_permissions", default=False)

    @property
    def key(self) -> str:
        """
        Returns a unique key for the dependency map based on its attributes.
        The key is a string representation of the catalog, schema, and table,
        formatted as 'catalog.schema.table', with all components in lowercase.
        """
        s = f".{self.catalog_schema}" if self.catalog_schema else ""
        t = f".{self.table}" if self.table else ""

        return f"{self.catalog}{s}{t}".lower()

class PrivilegeSnapshot(CommonBaseModel):
    """
    Represents a snapshot of privileges for a specific principal.
    This is used to capture the state of privileges at a specific point in time.
    Attributes:
        principal (Optional[str]): The identifier of the principal (user, service principal, or group
        type (Optional[IamType]): The type of the principal (user, service principal, or group).
        maps (Optional[Dict[str, DependencyMap]]): A dictionary mapping privilege names to their
            corresponding DependencyMap objects, which describe the dependencies of each privilege.
        group_membership (Optional[List[str]]): A list of group names that the principal is a member of.
    """
    principal: Optional[str] = Field(alias="principal", default=None)
    type: Optional[IamType] = Field(alias="type", default=None)
    maps: Optional[Dict[str, DependencyMap]] = Field(alias="maps", default={})    
    group_membership: Optional[List[str]] = Field(alias="group_membership", default=[])

class Privilege(CommonBaseModel):
    """
    Represents a privilege granted to a principal.
    This is used to define the access rights of a principal within the Databricks workspace.
    Attributes:
        principal (Optional[str]): The identifier of the principal (user, service principal, or group).
        privileges (Optional[List[str]]): A list of privileges granted to the principal.
        The `get_principal_type` method determines the type of the principal based on its identifier.
    """
    principal: Optional[str] = Field(alias="principal", default=None)
    privileges: Optional[List[str]] = Field(alias="privileges", default=None)

    def get_principal_type(self) -> IamType:
        """
        Determines the type of the principal based on its identifier.
        Returns:
            IamType: The type of the principal (USER, SERVICE_PRINCIPAL, or GROUP).
        """
        if Utils.is_email(self.principal):    
            return IamType.USER
        elif Utils.is_uuid(self.principal):
            return IamType.SERVICE_PRINCIPAL
        else:
            return IamType.GROUP

class BaseObject(CommonBaseModel):
    """
    Base class for objects in the Databricks model.
    This class provides a common structure for objects that can have an ID and a name.
    Attributes:
        id (Optional[str]): The unique identifier for the object.
        name (Optional[str]): The name of the object.
    """
    id: Optional[str] = Field(alias="id", default=None)
    name: Optional[str] = Field(alias="name", default=None)

class PrivilegedObject(BaseObject):
    """
    Represents an object that has privileges associated with it.
    This class extends BaseObject to include privileges that can be granted to principals.
    Attributes:
        privileges (Optional[List[Privilege]]): A list of privileges associated with the object.
    This allows the object to define what access rights are granted to different principals."""
    privileges: Optional[List[Privilege]] = Field(alias="privileges", default=None)

class FunctionMap(BaseObject):
    """
    Represents a mapping of a function to specific columns in a table.
    This class is used to define how a function applies to certain columns in a table.
    Attributes:
        function (Optional[str]): The name of the function being applied.
        columns (Optional[List[str]]): A list of column names to which the function applies.
    This allows the function to be applied selectively to specific columns in a table.
    """
    columns: Optional[List[str]] = Field(alias="column", default=None)

class Function(PrivilegedObject):
    """
    Represents a function that can be applied to data in the Databricks workspace.
    This class extends PrivilegedObject to include the SQL definition of the function.
    Attributes:
        sql (Optional[str]): The SQL definition of the function.
        This allows the function to be defined in SQL and applied to data as needed.
    """
    sql: Optional[str] = Field(alias="sql", default=None)

class Table(PrivilegedObject):
    """
    Represents a table in the Databricks workspace.
    This class extends PrivilegedObject to include additional attributes specific to tables.
    Attributes:
        catalog (Optional[str]): The name of the catalog that contains the table.
        schema (Optional[str]): The schema within the catalog that contains the table.
        column_masks (Optional[List[FunctionMap]]): A list of function maps that define how
            functions apply to specific columns in the table.
        row_filter (Optional[FunctionMap]): A function map that defines a filter to be applied
            to the rows of the table.
    This allows the table to define its structure and how functions can be applied to its data.
    """
    column_masks: Optional[List[FunctionMap]] = Field(
        alias="column_masks", default=None
    )
    row_filter: Optional[FunctionMap] = Field(alias="row_filter", default=None)

class Schema(PrivilegedObject):
    """
    Represents a schema within a catalog in the Databricks workspace.
    This class extends PrivilegedObject to include tables and mask functions associated with the schema.
    Attributes:
        catalog (Optional[str]): The name of the catalog that contains the schema.
        tables (Optional[List[Table]]): A list of tables within the schema.
        mask_functions (Optional[List[Function]]): A list of functions that define masking behavior
            for data in the schema. 
        This allows the schema to define its structure and the functions that can be applied to its data.
    """
    tables: Optional[List[Table]] = Field(alias="table", default=None)
    mask_functions: Optional[List[Function]] = Field(
        alias="mask_functions", default=None
    )

class Catalog(PrivilegedObject):
    """
    Represents a catalog in the Databricks workspace.
    This class extends PrivilegedObject to include schemas within the catalog.
    Attributes:
        schemas (Optional[List[Schema]]): A list of schemas within the catalog.
    This allows the catalog to define its structure and the schemas that it contains.
    """
    schemas: Optional[List[Schema]] = Field(alias="schemas", default=None)

class DatabricksUser(BaseObject):
    """
    Represents a user in the Databricks workspace.
    This class extends BaseObject to include additional attributes specific to users.
    Attributes:
        id (Optional[str]): The unique identifier for the user.
        name (Optional[str]): The name of the user.
        email (Optional[str]): The email address of the user.
        external_id (Optional[str]): An external identifier for the user, if applicable.
    """
    email: Optional[str] = Field(alias="email", default=None)
    external_id: Optional[str] = Field(alias="external_id", default=None)

class DatabricksServicePrincipal(BaseObject):
    """
    Represents a service principal in the Databricks workspace.
    This class extends BaseObject to include additional attributes specific to service principals.
    Attributes:
        id (Optional[str]): The unique identifier for the service principal.
        name (Optional[str]): The name of the service principal.
        application_id (Optional[str]): The application ID of the service principal.
        external_id (Optional[str]): An external identifier for the service principal, if applicable.
    """
    application_id: Optional[str] = Field(alias="application_id", default=None)
    external_id: Optional[str] = Field(alias="external_id", default=None)

class DatabricksGroupMember(BaseObject):
    """
    Represents a member of a Databricks group.
    This class extends BaseObject to include the type of the member.
    Attributes:
        id (Optional[str]): The unique identifier for the member.
        name (Optional[str]): The name of the member.
        type (Optional[IamType]): The type of the member (USER, SERVICE_PRINCIPAL, or GROUP).
    """
    type: Optional[IamType] = Field(alias="type", default=None)

class DatabricksGroup(BaseObject):
    """
    Represents a group in the Databricks workspace.
    This class extends BaseObject to include members of the group.
    Attributes:
        id (Optional[str]): The unique identifier for the group.
        name (Optional[str]): The name of the group.
        members (Optional[List[DatabricksGroupMember]]): A list of members in the group, which can include users, service principals, or other groups.
    """
    members: Optional[List[DatabricksGroupMember]] = Field(alias="members", default=None)

class Workspace(BaseObject):
    """
    Represents a Databricks workspace.
    This class extends BaseObject to include the catalog and identities associated with the workspace.
    Attributes:
        id (Optional[str]): The unique identifier for the workspace.
        name (Optional[str]): The name of the workspace.
        catalog (Optional[Catalog]): The catalog associated with the workspace, which contains schemas and tables.
        users (Optional[List[DatabricksUser]]): A list of users in the workspace.
        groups (Optional[List[DatabricksGroup]]): A list of groups in the workspace.
        service_principals (Optional[List[DatabricksServicePrincipal]]): A list of service principals in the workspace.
    This allows the workspace to define its structure and the identities that have access to it.
    """
    catalog: Optional[Catalog] = Field(alias="catalog", default=None)
    users: Optional[List[DatabricksUser]] = Field(alias="users", default=None)
    groups: Optional[List[DatabricksGroup]] = Field(alias="groups", default=None)
    service_principals: Optional[List[DatabricksServicePrincipal]] = Field(alias="service_principals", default=None)

    def get_workspace_identities(self, include_groups:bool=False) -> List[str]:
        """
        Returns a list of identities associated with the workspace.
        This includes user emails, service principal application IDs, and optionally group names.
        Args:
            include_groups (bool): If True, include group names in the list of identities.
         Returns:    
                List[str]: A list of identities associated with the workspace.
        """
        identities = []

        if self.users:
            identities.extend([u.email for u in self.users if u.email])

        if self.service_principals:
            identities.extend([s.application_id for s in self.service_principals if s.application_id])

        if include_groups and self.groups:
            identities.extend([g.name for g in self.groups if g.name])

        return identities
    
    def lookup_user_by_id(self, id: str) -> DatabricksUser:
        """
        Looks up a user by their unique identifier in the workspace.
        Args:
            id (str): The unique identifier of the user to look up.
        Returns:
            DatabricksUser: The user object if found, otherwise None.
        """
        user = list(filter(lambda u: u.id == id, self.users))

        if user:
            return user[0]

        return None

    def lookup_service_principal_by_id(self, id: str) -> DatabricksServicePrincipal:
        """
        Looks up a service principal by its application ID in the workspace.
        Args:
            id (str): The application ID of the service principal to look up.
        Returns:
            DatabricksServicePrincipal: The service principal object if found, otherwise None.
        """
        service_principal = list(filter(lambda s: s.application_id == id, self.service_principals))

        if service_principal:
            return service_principal[0]

        return None
    
    def lookup_user_by_email(self, email: str) -> DatabricksUser:
        """
        Looks up a user by their email address in the workspace.
        Args:
            email (str): The email address of the user to look up.
        Returns:
            DatabricksUser: The user object if found, otherwise None.
        """
        user = list(filter(lambda u: u.email == email, self.users))

        if user:
            return user[0]

        return None
    
    def lookup_group_by_name(self, name: str) -> DatabricksUser:
        """
        Looks up a group by its name in the workspace.
        Args:
            name (str): The name of the group to look up.
        Returns:
            DatabricksUser: The group object if found, otherwise None.
        """
        group = list(filter(lambda g: g.name == name, self.groups))

        if group:
            return group[0]
        
        return None
    
    def lookup_object_id(self, principal:str, type:IamType) -> str:
        """
        Looks up the object ID for a given principal based on its type.
        Args:
            principal (str): The identifier of the principal (email for user, application ID for service principal, or group name).
            type (IamType): The type of the principal (USER, SERVICE_PRINCIPAL, or GROUP).
        Returns:
            str: The object ID of the principal if found, otherwise None.
        """
        match type:
            case IamType.USER:
                u = self.lookup_user_by_email(principal)
                return u.id if u else None
            case IamType.SERVICE_PRINCIPAL:
                s = self.lookup_service_principal_by_id(principal)
                return s.application_id if s else None
            case _:
                g = self.lookup_group_by_name(principal)
                return g.id if g else None
    
    def get_user_groups(self, object_id:str) -> List[str]:
        """
        Returns a list of group names that the user with the given object ID is a member of.
        This method recursively flattens group memberships to ensure that all nested group memberships are included.
        Args:
            object_id (str): The unique identifier of the user for whom to retrieve group memberships.
        Returns:
            List[str]: A list of group names that the user is a member of, including nested group memberships.
        """
        membership = []
        
        for g in self.groups:
            membership = self.__extend_with_dedup__(membership, 
                                                    self.__flatten_group__(g.name, object_id))                  

        return list(set(membership))
    
    def __extend_with_dedup__(self, src, new):
        """
        Extends a source list with new items while ensuring no duplicates.
        This method combines two lists and removes duplicates by converting them to a set.
        Args:
            src (List[str]): The source list to extend.
            new (List[str]): The new items to add to the source list.
        Returns:
            List[str]: A new list containing unique items from both the source and new lists.
        """
        if not src or len(src) == 0:
            return new

        if not new or len(new) == 0:
            return src

        s = set(src)
        s.update(new)

        return list(s)
    
    def __flatten_group__(self, name: str, id: str) -> List[str]:
        """
        Recursively flattens group memberships to find all groups that a user is a member of.
        This method checks if a user is a member of a group and extends the membership list with nested group memberships.
        Args:
            name (str): The name of the group to check for membership.
            id (str): The unique identifier of the user to check for membership.
        Returns:
            List[str]: A list of group names that the user is a member of, including nested group memberships.
        """
        group = self.lookup_group_by_name(name)
        membership = []

        if group:
            for m in group.members:
                if m.type == IamType.USER and m.id == id:
                    if m.name not in membership:
                        membership.append(group.name)
                elif m.type == IamType.GROUP:
                    membership = self.__extend_with_dedup__(
                        membership, self.__flatten_group__(m.name, id)
                    )

        return membership

class Account(BaseObject):
    """
    Represents a Databricks account.
    This class extends BaseObject to include the account catalog and identities associated with the account.
    Attributes:
        acount_id (Optional[Catalog]): The catalog associated with the account, which contains schemas and tables.
        users (Optional[List[DatabricksUser]]): A list of users in the account.
        groups (Optional[List[DatabricksGroup]]): A list of groups in the account.
        service_principals (Optional[List[DatabricksServicePrincipal]]): A list of service principals in the account.
    """
    acount_id: Optional[Catalog] = Field(alias="acount_id", default=None)
    users: Optional[List[DatabricksUser]] = Field(alias="users", default=None)
    groups: Optional[List[DatabricksGroup]] = Field(alias="groups", default=None)
    service_principals: Optional[List[DatabricksServicePrincipal]] = Field(alias="service_principals", default=None)

    def lookup_service_principal_by_id(self, id: str) -> DatabricksServicePrincipal:
        """
        Looks up a service principal by its application ID in the account.
        Args:
            id (str): The application ID of the service principal to look up.
        Returns:
            DatabricksServicePrincipal: The service principal object if found, otherwise None.
        """
        service_principal = list(filter(lambda s: s.application_id == id, self.service_principals))

        if service_principal:
            return service_principal[0]

        return None
    
    def lookup_user_by_email(self, email: str) -> DatabricksUser:
        """
        Looks up a user by their email address in the account.
        Args:
            email (str): The email address of the user to look up.
        Returns:
            DatabricksUser: The user object if found, otherwise None.
        """
        user = list(filter(lambda u: u.email == email, self.users))

        if user:
            return user[0]

        return None
    
    def lookup_group_by_name(self, name: str) -> DatabricksUser:
        """
        Looks up a group by its name in the account.
        Args:
            name (str): The name of the group to look up.
        Returns:
            DatabricksUser: The group object if found, otherwise None.
        """
        group = list(filter(lambda g: g.name == name, self.groups))

        if group:
            return group[0]
        
        return None

class DatabricksSourceConfig(CommonBaseModel):
    """
    Represents the configuration for a Databricks source.
    This class includes the workspace URL, account ID, and account API token.
    Attributes:
        workspace_url (Optional[str]): The URL of the Databricks workspace.
        account_id (Optional[str]): The unique identifier for the Databricks account.
        account_api_token (Optional[str]): The API token for accessing the Databricks account.
    """
    workspace_url: Optional[str] = Field(alias="workspace_url", default=None)
    account_id: Optional[str] = Field(alias="account_id", default=None)
    account_api_token: Optional[str] = Field(alias="account_api_token", default=None)

class DatabricksSourceMap(SourceMap):
    databricks: Optional[DatabricksSourceConfig] = Field(alias="databricks", default=None)