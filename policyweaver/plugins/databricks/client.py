import json
import os
from pydantic.json import pydantic_encoder

from typing import List, Tuple
from policyweaver.models.export import (
    PolicyExport, Policy, Permission, PermissionObject
)
from policyweaver.plugins.databricks.model import (
    Privilege, PrivilegeSnapshot, DependencyMap, DatabricksSourceMap
)
from policyweaver.core.enum import (
    IamType, PermissionType, PermissionState, PolicyWeaverConnectorType
)

from policyweaver.core.utility import Utils
from policyweaver.core.common import PolicyWeaverCore
from policyweaver.plugins.databricks.api import DatabricksAPIClient

class DatabricksPolicyWeaver(PolicyWeaverCore):
    """
        Databricks Policy Weaver for Unity Catalog.
        This class extends the PolicyWeaverCore to implement the mapping of policies
        from Databricks Unity Catalog to the Policy Weaver framework.
    """
    dbx_account_users_group = "account users"
    dbx_all_permissions = ["ALL_PRIVILEGES"]
    dbx_read_permissions = ["SELECT"] + dbx_all_permissions
    dbx_catalog_read_prereqs = ["USE_CATALOG"] + dbx_all_permissions
    dbx_schema_read_prereqs = ["USE_SCHEMA"] + dbx_all_permissions

    def __init__(self, config:DatabricksSourceMap) -> None:
        """
        Initializes the DatabricksPolicyWeaver with the provided configuration.
        Args:
            config (DatabricksSourceMap): The configuration object containing the workspace URL, account ID, and API token.
        Raises:
            ValueError: If the configuration is not of type DatabricksSourceMap.
        """
        super().__init__(PolicyWeaverConnectorType.UNITY_CATALOG, config)

        self.__config_validation(config)
        self.__init_environment(config)
        
        self.workspace = None
        self.account = None
        self.snapshot = {}
        self.api_client = DatabricksAPIClient()

    def __init_environment(self, config:DatabricksSourceMap) -> None:
        os.environ["DBX_HOST"] = config.databricks.workspace_url
        os.environ["DBX_ACCOUNT_ID"] = config.databricks.account_id
        os.environ["DBX_ACCOUNT_API_TOKEN"] = config.databricks.account_api_token

    def __config_validation(self, config:DatabricksSourceMap) -> None:
        """
        Validates the configuration for the DatabricksPolicyWeaver.
        This method checks if the configuration is of type DatabricksSourceMap and if all required fields are present.
        Args:
            config (DatabricksSourceMap): The configuration object to validate.
        Raises:
            ValueError: If the configuration is not of type DatabricksSourceMap or if any required fields are missing.
        """
        if not config.databricks:
            raise ValueError("DatabricksSourceMap configuration is required for DatabricksPolicyWeaver.")
        
        if not config.databricks.workspace_url:
            raise ValueError("Databricks workspace URL is required in the configuration.")
        
        if not config.databricks.account_id:
            raise ValueError("Databricks account ID is required in the configuration.")
        
        if not config.databricks.account_api_token:
            raise ValueError("Databricks account API token is required in the configuration.")

    def map_policy(self) -> PolicyExport:
        """
        Maps the policies from the Databricks Unity Catalog to the Policy Weaver framework.
        This method collects privileges from the workspace catalog, schemas, and tables,
        applies the access model, and builds the export policies.
        Returns:
            PolicyExport: An object containing the source, type, and policies mapped from the Databricks Unity Catalog.
        Raises:
            ValueError: If the source is not of type DatabricksSourceMap.
        """
        self.account, self.workspace = self.api_client.get_workspace_policy_map(self.config.source)
        self.__collect_privileges__(self.workspace.catalog.privileges, self.workspace.catalog.name)        

        for schema in self.workspace.catalog.schemas:
            self.__collect_privileges__(schema.privileges, self.workspace.catalog.name, schema.name)            

            for tbl in schema.tables:
                self.__collect_privileges__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name)                

        self.__apply_access_model__()

        policies = self.__build_export_policies__()

        return PolicyExport(source=self.config.source, type=self.connector_type, policies=policies)
    
    def __get_three_part_key__(self, catalog:str, schema:str=None, table:str=None) -> str:
        """
        Constructs a three-part key for the catalog, schema, and table.
        Args:
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            str: A string representing the three-part key in the format "catalog.schema.table".
        """
        schema = f".{schema}" if schema else ""
        table = f".{table}" if table else ""

        return f"{catalog}{schema}{table}"
    
    def __resolve_principal_type__(self, principal:str) -> IamType:
        """
        Resolves the type of the principal based on its format.
        Args:
            principal (str): The principal identifier (email, UUID, or group name).
        Returns:
            IamType: The type of the principal (USER, SERVICE_PRINCIPAL, or GROUP).
        """
        if Utils.is_email(principal):
            return IamType.USER
        elif Utils.is_uuid(principal):
            return IamType.SERVICE_PRINCIPAL
        else:
            return IamType.GROUP
        
    def __collect_privileges__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> None:
        """
        Collects privileges from the provided list and maps them to the snapshot.
        This method creates a DependencyMap for each privilege and adds it to the snapshot.
        Args:
            privileges (List[Privilege]): A list of Privilege objects to collect.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        """
        for privilege in privileges:
            dependency_map = DependencyMap(
                catalog=catalog,
                schema=schema,
                table=table
                )

            if privilege.privileges:
                for p in privilege.privileges:
                    dependency_map.privileges.append(p)
                    
                    if privilege.principal not in self.snapshot:
                        self.snapshot[privilege.principal] = PrivilegeSnapshot(
                                principal=privilege.principal,
                                type=self.__resolve_principal_type__(privilege.principal),
                                maps={dependency_map.key: dependency_map}
                            )
                    else:
                        if dependency_map.key not in self.snapshot[privilege.principal].maps:
                            self.snapshot[privilege.principal].maps[dependency_map.key] = dependency_map
                        else:
                            if p not in self.snapshot[privilege.principal].maps[dependency_map.key].privileges:
                                self.snapshot[privilege.principal].maps[dependency_map.key].privileges.append(p)
    
    def __search_privileges__(self, snapshot:PrivilegeSnapshot, key:str, prereqs:List[str]) -> bool:
        """
        Searches for privileges in the snapshot that match the given key and prerequisites.
        Args:
            snapshot (PrivilegeSnapshot): The snapshot containing the privileges.
            key (str): The key to search for in the snapshot.
            prereqs (List[str]): A list of prerequisite privileges to check against.
        Returns:
            bool: True if any privileges match the key and prerequisites, False otherwise.
        """
        if key in snapshot.maps:
            if [p for p in snapshot.maps[key].privileges if p in prereqs]:
                return True
        
        return False
    
    def __apply_access_model__(self) -> None:
        """
        Applies the access model to the snapshot by ensuring that all users, service principals, and groups
        are represented in the snapshot. It also applies privilege inheritance and group membership.
        This method ensures that all principals have a PrivilegeSnapshot and that their privileges are inherited correctly.
        It also collects group memberships for each principal.
        Returns:
            None
        """
        for workspace_user in self.workspace.users:
            if workspace_user.email not in self.snapshot:
                self.snapshot[workspace_user.email] = PrivilegeSnapshot(
                    principal=workspace_user.email,
                    type=IamType.USER,
                    maps={}
                )
        
        for workspace_service_principal in self.workspace.service_principals:
            if workspace_service_principal.application_id not in self.snapshot:
                self.snapshot[workspace_service_principal.application_id] = PrivilegeSnapshot(
                    principal=workspace_service_principal.application_id,
                    type=IamType.SERVICE_PRINCIPAL,
                    maps={}
                )
                
        for workspace_group in self.workspace.groups:
            if workspace_group.name not in self.snapshot:
                self.snapshot[workspace_group.name] = PrivilegeSnapshot(
                    principal=workspace_group.name,
                    type=IamType.GROUP,
                    maps={}
                )

        for principal in self.snapshot:
            self.snapshot[principal] = self.__apply_privilege_inheritence__(self.snapshot[principal])

            object_id = self.workspace.lookup_object_id(principal, self.snapshot[principal].type)
            
            if object_id:
                self.snapshot[principal].group_membership = self.workspace.get_user_groups(object_id)
            
            self.snapshot[principal].group_membership.append(self.dbx_account_users_group)
            #self.logger.debug(f"DBX Snapshot - Principal ({principal}) - {self.snapshot[principal].model_dump_json(indent=4)}") 

    def __apply_privilege_inheritence__(self, privilege_snapshot:PrivilegeSnapshot) -> PrivilegeSnapshot:
        """
        Applies privilege inheritance to the given PrivilegeSnapshot.
        This method ensures that catalog and schema prerequisites are set for each map in the snapshot.
        Args:
            privilege_snapshot (PrivilegeSnapshot): The PrivilegeSnapshot to apply inheritance to.
        Returns:
            PrivilegeSnapshot: The updated PrivilegeSnapshot with applied privilege inheritance.
        """
        for map_key in privilege_snapshot.maps:
            map = privilege_snapshot.maps[map_key]
            catalog_key = None if not map.catalog else self.__get_three_part_key__(map.catalog)
            schema_key = None if not map.catalog_schema else self.__get_three_part_key__(map.catalog, map.catalog_schema)

            if catalog_key in privilege_snapshot.maps:
                privilege_snapshot.maps[map_key].catalog_all_cascade = \
                    self.__search_privileges__(privilege_snapshot, catalog_key, self.dbx_all_permissions)
                privilege_snapshot.maps[map_key].catalog_prerequisites = \
                    privilege_snapshot.maps[map_key].catalog_all_cascade if privilege_snapshot.maps[map_key].catalog_all_cascade else \
                        self.__search_privileges__(privilege_snapshot, catalog_key, self.dbx_catalog_read_prereqs)
                
            sk = schema_key if schema_key and schema_key in privilege_snapshot.maps else map_key

            privilege_snapshot.maps[map_key].schema_all_cascade = \
                self.__search_privileges__(privilege_snapshot, sk, self.dbx_all_permissions)    
            privilege_snapshot.maps[map_key].schema_prerequisites = \
                privilege_snapshot.maps[map_key].schema_all_cascade if privilege_snapshot.maps[map_key].schema_all_cascade else \
                    self.__search_privileges__(privilege_snapshot, sk, self.dbx_schema_read_prereqs)
                
            privilege_snapshot.maps[map_key].read_permissions = \
                self.__search_privileges__(privilege_snapshot, map_key, self.dbx_read_permissions)
   
        return privilege_snapshot

    def __build_export_policies__(self) -> List[Policy]:
        """
        Builds the export policies from the collected privileges in the snapshot.
        This method constructs Policy objects for each catalog, schema, and table,
        applying the read permissions and prerequisites.
        Returns:
            List[Policy]: A list of Policy objects representing the export policies.
        """
        policies = []

        if self.workspace.catalog.privileges:
            policies.append(
                self.__build_policy__(
                    self.__get_read_permissions__(self.workspace.catalog.privileges, self.workspace.catalog.name),
                    self.workspace.catalog.name))
        
        for schema in self.workspace.catalog.schemas:
            if schema.privileges:
                policies.append(
                    self.__build_policy__(
                        self.__get_read_permissions__(schema.privileges, self.workspace.catalog.name, schema.name),
                        self.workspace.catalog.name, schema.name))

            for tbl in schema.tables:
                if tbl.privileges:
                    policies.append(
                        self.__build_policy__(
                            self.__get_read_permissions__(tbl.privileges, self.workspace.catalog.name, schema.name, tbl.name),
                            self.workspace.catalog.name, schema.name, tbl.name))
        

        return policies

    def __build_policy__(self, table_permissions, catalog, schema=None, table=None) -> Policy:
        """
        Builds a Policy object from the provided table permissions, catalog, schema, and table.
        Args:
            table_permissions (List[str]): A list of user or service principal identifiers with read permissions.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            Policy: A Policy object containing the catalog, schema, table, and permissions."""
        policy = Policy(
            catalog=catalog,
            catalog_schema=schema,
            table=table,
            permissions=[]
        )

        permission = Permission(
                    name=PermissionType.SELECT,
                    state=PermissionState.GRANT,
                    objects=[])
        
        for p in table_permissions:
            po = PermissionObject() 
            po.type=IamType.USER if Utils.is_email(p) else IamType.SERVICE_PRINCIPAL

            if po.type == IamType.USER:
                u = self.workspace.lookup_user_by_email(p)
        
                if u:
                    po.id = u.external_id
                    po.email = p
                    self.logger.debug(f"DBX User Lookup {p} - ID {u.external_id}")
                else:
                    self.logger.debug(f"DBX User Lookup {p} - not found, using email...")
                    po.email = p
            elif po.type == IamType.SERVICE_PRINCIPAL:
                s = self.workspace.lookup_service_principal_by_id(p)

                if s:
                    po.id = s.external_id
                    po.app_id = p
                    self.logger.debug(f"DBX Service Principal ID Lookup {p} - ID {s.external_id}")
                else:
                    self.logger.debug(f"DBX Service Principal ID Lookup {p} - not found...")
                    po.app_id = p
            
            permission.objects.append(po)

        if len(permission.objects) > 0:
            policy.permissions.append(permission)

        self.logger.debug(f"DBX Policy Export - {policy.catalog}.{policy.catalog_schema}.{policy.table} - {json.dumps(policy, default=pydantic_encoder, indent=4)}")
        return policy

    def __get_key_set__(self, key) -> List[str]:
        """
        Generates a set of keys from a given key string by splitting it on periods.
        Args:
            key (str): The key string to split into a set of keys.
        Returns:
            List[str]: A list of keys generated from the input key string.
        """
        keys = key.split(".")
        key_set = []

        for i in range(0, len(keys)):
            key_set.append(".".join(keys[0:i+1]))

        return key_set
    
    def __get_user_key_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
        """
        Retrieves the permissions for a user or service principal for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            Tuple[bool, bool, bool]: A tuple containing three boolean values indicating:
                - Whether the principal has catalog prerequisites.
                - Whether the principal has schema prerequisites.
                - Whether the principal has read permissions.
        """
        if principal in self.snapshot and key in self.snapshot[principal].maps:
            catalog_prereq = self.snapshot[principal].maps[key].catalog_prerequisites
            schema_prereq = self.snapshot[principal].maps[key].schema_prerequisites
            read_permission = self.snapshot[principal].maps[key].read_permissions

            self.logger.debug(f"DBX Evaluate - Principal ({principal}) Key ({key}) - {catalog_prereq}|{schema_prereq}|{read_permission}")
            
            if self.snapshot[principal].maps[key].catalog_all_cascade or self.snapshot[principal].maps[key].schema_all_cascade:
                return True, True, True

            return catalog_prereq, schema_prereq, read_permission
        else:
            return False, False, False 

    def __coalesce_user_group_permissions__(self, principal:str, key:str) -> Tuple[bool, bool, bool]:
        """
        Coalesces the permissions of a user or service principal with their group memberships for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            Tuple[bool, bool, bool]: A tuple containing three boolean values indicating:
                - Whether the principal has catalog prerequisites.
                - Whether the principal has schema prerequisites.
                - Whether the principal has read permissions.
        """
        catalog_prereq = False
        schema_prereq = False
        read_permission = False

        for member_group in self.snapshot[principal].group_membership:
            key_set = self.__get_key_set__(key)
            for k in key_set:
                c, s, r = self.__get_user_key_permissions__(member_group, k)                

                catalog_prereq = catalog_prereq if catalog_prereq else c
                schema_prereq = schema_prereq if schema_prereq else s
                read_permission = read_permission if read_permission else r
                self.logger.debug(f"DBX Evaluate - Principal ({principal}) Group ({member_group}) Key ({k}) - {catalog_prereq}|{schema_prereq}|{read_permission}")

                if catalog_prereq and schema_prereq and read_permission:
                    break
            
            if catalog_prereq and schema_prereq and read_permission:
                    break
        
        return catalog_prereq, schema_prereq, read_permission

    def __has_read_permissions__(self, principal:str, key:str) -> bool:
        """
        Checks if a user or service principal has read permissions for a given key.
        Args:
            principal (str): The principal identifier (email or UUID).
            key (str): The key representing the catalog, schema, or table.
        Returns:
            bool: True if the principal has read permissions for the key, False otherwise.
        """
        catalog_prereq, schema_prereq, read_permission = self.__get_user_key_permissions__(principal, key)

        if not (catalog_prereq and schema_prereq and read_permission):
            group_catalog_prereq, _group_schema_prereq, group_read_permission = self.__coalesce_user_group_permissions__(principal, key)

            catalog_prereq = catalog_prereq if catalog_prereq else group_catalog_prereq
            schema_prereq = schema_prereq if schema_prereq else _group_schema_prereq
            read_permission = read_permission if read_permission else group_read_permission

        return catalog_prereq and schema_prereq and read_permission
    
    def __is_in_group__(self, principal:str, group:str) -> bool:
        """
        Checks if a user or service principal is a member of a specified group.
        Args:
            principal (str): The principal identifier (email or UUID).
            group (str): The name of the group to check membership against.
        Returns:
            bool: True if the principal is a member of the group, False otherwise.
        """
        if principal in self.snapshot:            
            if group in self.snapshot[principal].group_membership:
                return True

        return False
    
    def __get_read_permissions__(self, privileges:List[Privilege], catalog:str, schema:str=None, table:str=None) -> List[str]:
        """
        Retrieves the read permissions for a given catalog, schema, and table.
        This method checks the privileges for each principal and returns a list of user or service principal identifiers
        that have read permissions for the specified key.
        Args:
            privileges (List[Privilege]): A list of Privilege objects to check for read permissions.
            catalog (str): The name of the catalog.
            schema (str, optional): The name of the schema. Defaults to None.
            table (str, optional): The name of the table. Defaults to None.
        Returns:
            List[str]: A list of user or service principal identifiers that have read permissions for the specified key.
        """
        user_permissions = []

        key = self.__get_three_part_key__(catalog, schema, table)

        for r in privileges:
            if any(p in self.dbx_read_permissions for p in r.privileges):
                if self.__has_read_permissions__(r.principal, key):
                    if r.get_principal_type() == IamType.GROUP: 
                        indentities = self.workspace.get_workspace_identities()

                        for identity in indentities:
                            if self.__is_in_group__(identity, r.principal):
                                if not identity in user_permissions:
                                    self.logger.debug(f"DBX User ({identity}) added by {r.principal} group for {key}...")
                                    user_permissions.append(identity)
                    else:
                        if not r.principal in user_permissions:
                            self.logger.debug(f"DBX Principal ({r.principal}) direct add for {key}...")
                            user_permissions.append(r.principal)
                else:
                    self.logger.debug(f"DBX Principal ({r.principal}) does not have read permissions for {key}...")

        return user_permissions