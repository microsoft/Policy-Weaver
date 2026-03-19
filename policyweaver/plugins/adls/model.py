from pydantic import Field
from typing import Optional, List

from policyweaver.models.common import CommonBaseModel
from policyweaver.models.config import SourceMap


class AdlsAclPermission(CommonBaseModel):
    """
    Represents a single parsed ACL permission entry from a POSIX ACL string.
    Attributes:
        scope (str): 'access' or 'default'.
        type (str): 'user', 'group', 'mask', or 'other'.
        identifier (str): The OID/UPN of the principal, or empty for owning user/group/other.
        read (bool): Whether read permission is granted.
        write (bool): Whether write permission is granted.
        execute (bool): Whether execute permission is granted.
    """
    scope: Optional[str] = Field(alias="scope", default="access")
    type: Optional[str] = Field(alias="type", default=None)
    identifier: Optional[str] = Field(alias="identifier", default=None)
    read: Optional[bool] = Field(alias="read", default=False)
    write: Optional[bool] = Field(alias="write", default=False)
    execute: Optional[bool] = Field(alias="execute", default=False)


class AdlsPrincipal(CommonBaseModel):
    """
    Represents a resolved principal (user or group) from an ACL entry.
    Attributes:
        object_id (str): The Azure AD Object ID of the principal.
        display_name (str): The display name of the principal.
        principal_type (str): 'user' or 'group'.
        email (str): Email address if available (for users).
    """
    object_id: Optional[str] = Field(alias="object_id", default=None)
    display_name: Optional[str] = Field(alias="display_name", default=None)
    principal_type: Optional[str] = Field(alias="principal_type", default=None)
    email: Optional[str] = Field(alias="email", default=None)


class AdlsPathAcl(CommonBaseModel):
    """
    Represents the full ACL information for a single ADLS Gen2 path.
    Attributes:
        container (str): The container (filesystem) name.
        path (str): The path within the container.
        is_directory (bool): Whether this path is a directory.
        owner (str): The owner OID of the path.
        group (str): The owning group OID of the path.
        permissions (str): The POSIX permission string (e.g. 'rwxr-x---').
        acl_entries (List[AdlsAclPermission]): Parsed ACL entries.
    """
    container: Optional[str] = Field(alias="container", default=None)
    path: Optional[str] = Field(alias="path", default=None)
    is_directory: Optional[bool] = Field(alias="is_directory", default=True)
    owner: Optional[str] = Field(alias="owner", default=None)
    group: Optional[str] = Field(alias="group", default=None)
    permissions: Optional[str] = Field(alias="permissions", default=None)
    acl_entries: List[AdlsAclPermission] = Field(alias="acl_entries", default_factory=list)


class AdlsGrant(CommonBaseModel):
    """
    Represents a normalised grant derived from an ADLS ACL entry.
    Analogous to SnowflakeGrant, this maps a principal to a permission on a path.
    Attributes:
        principal_id (str): The Azure AD Object ID of the grantee.
        principal_type (str): 'user' or 'group'.
        container (str): The ADLS container name.
        path (str): The path within the container.
        is_directory (bool): Whether the path is a directory.
        read (bool): Read permission granted.
        write (bool): Write permission granted.
        execute (bool): Execute permission granted.
        acl_scope (str): 'access' or 'default'.
    """
    principal_id: Optional[str] = Field(alias="principal_id", default=None)
    principal_type: Optional[str] = Field(alias="principal_type", default=None)
    container: Optional[str] = Field(alias="container", default=None)
    path: Optional[str] = Field(alias="path", default=None)
    is_directory: Optional[bool] = Field(alias="is_directory", default=True)
    read: Optional[bool] = Field(alias="read", default=False)
    write: Optional[bool] = Field(alias="write", default=False)
    execute: Optional[bool] = Field(alias="execute", default=False)
    acl_scope: Optional[str] = Field(alias="acl_scope", default="access")


class AdlsDatabaseMap(CommonBaseModel):
    """
    A collection of ADLS path ACLs, grants, and principals for a storage account.
    Analogous to SnowflakeDatabaseMap.
    Attributes:
        path_acls (List[AdlsPathAcl]): All scanned path ACL records.
        grants (List[AdlsGrant]): Normalised grants derived from ACLs.
        principals (List[AdlsPrincipal]): Resolved principals from ACL entries.
    """
    path_acls: List[AdlsPathAcl] = Field(alias="path_acls", default_factory=list)
    grants: List[AdlsGrant] = Field(alias="grants", default_factory=list)
    principals: List[AdlsPrincipal] = Field(alias="principals", default_factory=list)


class AdlsConnection(CommonBaseModel):
    """
    Represents a connection to an Azure Data Lake Storage Gen2 account.
    Attributes:
        account_url (str): The account URL (e.g. https://<acct>.dfs.core.windows.net).
        tenant_id (str): The Azure AD tenant ID for service principal authentication.
        client_id (str): The client ID of the service principal.
        client_secret (str): The client secret of the service principal.
    """
    account_url: Optional[str] = Field(alias="account_url", default=None)
    tenant_id: Optional[str] = Field(alias="tenant_id", default=None)
    client_id: Optional[str] = Field(alias="client_id", default=None)
    client_secret: Optional[str] = Field(alias="client_secret", default=None)


class AdlsSourceConfig(CommonBaseModel):
    """
    Represents the configuration for an ADLS Gen2 source.
    Attributes:
        account_url (str): The account URL (e.g. https://<acct>.dfs.core.windows.net).
        container (str): Optional specific container to scan (default: all).
        path (str): Starting path within the container (default: root).
        max_depth (int): Max recursion depth (-1 = unlimited).
    """
    account_url: Optional[str] = Field(alias="account_url", default=None)
    container: Optional[str] = Field(alias="container", default=None)
    path: Optional[str] = Field(alias="path", default="")
    max_depth: Optional[int] = Field(alias="max_depth", default=-1)


class AdlsSourceMap(SourceMap):
    """
    Represents the configuration for an ADLS Gen2 source map.
    This class extends SourceMap to include ADLS-specific configuration.
    Attributes:
        adls (AdlsSourceConfig): The ADLS source configuration.
    """
    adls: Optional[AdlsSourceConfig] = Field(alias="adls", default=None)
