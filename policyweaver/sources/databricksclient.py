import re
from databricks.sdk import WorkspaceClient
from typing import List
from databricks.sdk.errors import NotFound
from databricks.sdk.service.catalog import SecurableType

from policyweaver.models.databricksmodel import (
    Workspace,
    Catalog,
    Schema,
    Table,
    Privilege,
    Function,
    FunctionMap,
    WorkspaceUser,
    WorkspaceGroup,
    WorkspaceGroupMember,
)

from policyweaver.models.common import (
    IamType,
    Permission,
    PermissionObject,
    PermissionState,
    PermissionType,
    PolicyExport,
    Policy,
    PolicyWeaverConnectorType,
    SourceSchema,
    Source,
)
from policyweaver.weavercore import PolicyWeaverCore


class DatabricksAPIClient:
    def __init__(self, workspace: str, token: str):
        self.workspace_client = WorkspaceClient(host=workspace, token=token)

    def get_workspace_policy_map(self, source: Source) -> Workspace:
        try:
            api_catalog = self.workspace_client.catalogs.get(source.name)

            return Workspace(
                catalog=Catalog(
                    name=api_catalog.name,
                    schemas=self.__get_catalog_schemas__(
                        api_catalog.name, source.schemas
                    ),
                    privileges=self.__get_privileges__(
                        SecurableType.CATALOG, api_catalog.name
                    ),
                ),
                users=self.__get_workspace_users__(),
                groups=self.__get_workspace_groups__(),
            )
            return
        except NotFound:
            return None

    def __get_workspace_users__(self):
        return [
            WorkspaceUser(
                id=u.id,
                name=u.display_name,
                email="".join([e.value for e in u.emails if e.primary]),
            )
            for u in self.workspace_client.users.list()
        ]

    def __get_workspace_groups__(self):
        return [
            WorkspaceGroup(
                id=g.id,
                name=g.display_name,
                members=[
                    WorkspaceGroupMember(
                        id=m.value,
                        name=m.display,
                        type=IamType.USER
                        if m.ref.find("Users") > -1
                        else IamType.GROUP,
                    )
                    for m in g.members
                ],
            )
            for g in self.workspace_client.groups.list()
        ]

    def __get_privileges__(self, type: SecurableType, name) -> List[Privilege]:
        api_privileges = self.workspace_client.grants.get(
            securable_type=type, full_name=name
        )

        return [
            Privilege(principal=p.principal, privileges=[e.value for e in p.privileges])
            for p in api_privileges.privilege_assignments
        ]

    def __get_schema_from_list__(self, schema_list, schema):
        if schema_list:
            search = [s for s in schema_list if s.name == schema]

            if search:
                return search[0]

        return None

    def __get_catalog_schemas__(
        self, catalog: str, schema_filters: List[SourceSchema]
    ) -> List[Schema]:
        api_schemas = self.workspace_client.schemas.list(catalog_name=catalog)

        if schema_filters:
            filter = [s.name for s in schema_filters]
            api_schemas = [s for s in api_schemas if s.name in filter]

        schemas = []

        for s in api_schemas:
            schema_filter = self.__get_schema_from_list__(schema_filters, s.name)

            tbls = self.__get_schema_tables__(
                catalog=catalog,
                schema=s.name,
                table_filters=None if not schema_filters else schema_filter.tables,
            )

            schemas.append(
                Schema(
                    name=s.name,
                    tables=tbls,
                    privileges=self.__get_privileges__(
                        SecurableType.SCHEMA, s.full_name
                    ),
                    mask_functions=self.__get_column_mask_functions__(
                        catalog, s.name, tbls
                    ),
                )
            )

        return schemas

    def __get_schema_tables__(
        self, catalog: str, schema: str, table_filters: List[str]
    ) -> List[Table]:
        api_tables = self.workspace_client.tables.list(
            catalog_name=catalog, schema_name=schema
        )

        if table_filters:
            api_tables = [t for t in api_tables if t.name in table_filters]

        return [
            Table(
                name=t.name,
                row_filter=None
                if not t.row_filter
                else FunctionMap(
                    name=t.row_filter.function_name,
                    columns=t.row_filter.input_column_names,
                ),
                column_masks=[
                    FunctionMap(
                        name=c.mask.function_name, columns=c.mask.using_column_names
                    )
                    for c in t.columns
                    if c.mask
                ],
                privileges=self.__get_privileges__(SecurableType.TABLE, t.full_name),
            )
            for t in api_tables
        ]

    def __get_column_mask_functions__(
        self, catalog: str, schema: str, tables: List[Table]
    ) -> List[Function]:
        inscope = []

        for t in tables:
            if t.row_filter:
                if t.row_filter.name not in inscope:
                    inscope.append(t.row_filter.name)

            if t.column_masks:
                for m in t.column_masks:
                    if m.name not in inscope:
                        inscope.append(m.name)

        return [
            Function(
                name=f.full_name,
                sql=f.routine_definition,
                privileges=self.__get_privileges__(SecurableType.FUNCTION, f.full_name),
            )
            for f in self.workspace_client.functions.list(
                catalog_name=catalog, schema_name=schema
            )
            if f.full_name in inscope
        ]


class DatabricksPolicyWeaver(PolicyWeaverCore):
    dbx_read_permissions = ["SELECT", "ALL_PRIVILEGES"]

    def __init__(self, workspace: str, token: str):
        super().__init__(PolicyWeaverConnectorType.UNITY_CATALOG)
        self.workspace = None
        self.api_client = DatabricksAPIClient(workspace=workspace, token=token)

    def map_policy(self, source: Source) -> PolicyExport:
        self.workspace = self.api_client.get_workspace_policy_map(source)

        policies = []

        catalog_permissions = self.__get_read_permissions__(
            self.workspace.catalog.privileges
        )

        if catalog_permissions:
            policies.append(
                self.__build_policy__(
                    catalog=self.workspace.catalog.name,
                    schema=None,
                    table=None,
                    table_permissions=catalog_permissions,
                )
            )

        for schema in self.workspace.catalog.schemas:
            schema_permissions = self.__get_read_permissions__(schema.privileges)

            if schema_permissions:
                policies.append(
                    self.__build_policy__(
                        catalog=self.workspace.catalog.name,
                        schema=schema.name,
                        table=None,
                        table_permissions=schema_permissions,
                    )
                )

            for tbl in schema.tables:
                tbl_permissions = self.__get_read_permissions__(tbl.privileges)

                if tbl_permissions:
                    policies.append(
                        self.__build_policy__(
                            catalog=self.workspace.catalog.name,
                            schema=schema.name,
                            table=tbl.name,
                            table_permissions=tbl_permissions,
                        )
                    )

        self.__write_to_log__(self.connector_type, self.workspace.model_dump())

        return PolicyExport(source=source, type=self.connector_type, policies=policies)

    def __build_policy__(self, catalog, schema, table, table_permissions):
        return Policy(
            catalog=catalog,
            catalog_schema=schema,
            table=table,
            permissions=[
                Permission(
                    name=PermissionType.SELECT,
                    state=PermissionState.GRANT,
                    objects=[
                        PermissionObject(id=p, type=IamType.USER)
                        for p in table_permissions
                    ],
                )
            ],
        )

    def __get_read_permissions__(self, privileges):
        user_permissions = []

        for r in privileges:
            if any(p in self.dbx_read_permissions for p in r.privileges):
                if self.__is_email__(r.principal):
                    user_permissions.append(r.principal)
                else:
                    user_permissions = self.__extend_with_dedup__(
                        user_permissions, self.__flatten_group__(r.principal)
                    )

        return user_permissions

    def __is_email__(self, email):
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(pattern, email)

    def __lookup_user__(self, id: str) -> WorkspaceUser:
        user = list(filter(lambda u: u.id == id, self.workspace.users))

        if not user:
            return None

        return user[0]

    def __lookup_group_by_name__(self, name: str) -> WorkspaceUser:
        group = list(filter(lambda g: g.name == name, self.workspace.groups))

        if not group:
            return None

        return group[0]

    def __extend_with_dedup__(self, src, new):
        if not src or len(src) == 0:
            return new

        if not new or len(new) == 0:
            return src

        s = set(src)
        s.update(new)

        return list(s)

    def __flatten_group__(self, name: str) -> List[str]:
        group = self.__lookup_group_by_name__(name)
        group_users = []

        if group:
            for m in group.members:
                if m.type == IamType.USER:
                    u = self.__lookup_user__(m.id)
                    group_users.append(u.email)
                elif m.type == IamType.GROUP:
                    group_users = self.__extend_with_dedup__(
                        group_users, self.__flatten_group__(m.name)
                    )

        return group_users
