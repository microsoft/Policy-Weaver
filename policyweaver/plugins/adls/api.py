import logging
import re
from typing import List, Optional

from azure.storage.filedatalake import DataLakeServiceClient
from azure.identity import ClientSecretCredential

from policyweaver.models.config import Source
from policyweaver.plugins.adls.model import (
    AdlsAclPermission,
    AdlsConnection,
    AdlsDatabaseMap,
    AdlsGrant,
    AdlsPathAcl,
    AdlsPrincipal,
)


class AdlsAPIClient:
    """
    ADLS Gen2 API Client for extracting POSIX ACLs from Azure Data Lake Storage.
    This client uses the azure-storage-file-datalake SDK to scan containers and paths,
    parse POSIX ACL strings, and produce structured ACL data for policy mapping.
    """

    def __init__(self, connection: AdlsConnection):
        """
        Initializes the ADLS API Client with a connection to the storage account.
        Args:
            connection (AdlsConnection): Connection configuration for the ADLS account.
        """
        self.logger = logging.getLogger("POLICY_WEAVER")
        self.connection = connection
        self.service_client = self.__build_service_client__()

    def __build_service_client__(self) -> DataLakeServiceClient:
        """
        Build a DataLakeServiceClient using service principal (ClientSecretCredential).
        Returns:
            DataLakeServiceClient: A connected service client.
        """
        credential = ClientSecretCredential(
            tenant_id=self.connection.tenant_id,
            client_id=self.connection.client_id,
            client_secret=self.connection.client_secret,
        )
        return DataLakeServiceClient(
            self.connection.account_url, credential=credential
        )

    @staticmethod
    def parse_acl_string(acl_string: str) -> List[AdlsAclPermission]:
        """
        Parse a POSIX ACL string into a list of AdlsAclPermission objects.
        ACL format: 'scope:type:id:permissions' entries separated by commas.
        Example: 'user::rwx,user:OID:r-x,group::r-x,mask::rwx,other::---,default:user:OID:rwx'
        Args:
            acl_string (str): The raw ACL string from ADLS.
        Returns:
            List[AdlsAclPermission]: Parsed ACL permission entries.
        """
        if not acl_string:
            return []

        entries = []
        for part in acl_string.split(","):
            part = part.strip()
            if not part:
                continue

            tokens = part.split(":")
            scope = "access"

            if tokens[0] == "default":
                scope = "default"
                tokens = tokens[1:]

            if len(tokens) < 3:
                continue

            acl_type = tokens[0]  # user, group, mask, other
            identifier = tokens[1]  # OID or empty
            perms = tokens[2] if len(tokens) > 2 else "---"

            entries.append(
                AdlsAclPermission(
                    scope=scope,
                    type=acl_type,
                    identifier=identifier if identifier else None,
                    read="r" in perms,
                    write="w" in perms,
                    execute="x" in perms,
                )
            )

        return entries

    def __get_acl_for_path__(self, fs_client, path: str, is_directory: bool) -> Optional[AdlsPathAcl]:
        """
        Retrieve ACL info for a single path.
        Args:
            fs_client: The file system client for the container.
            path (str): The path to retrieve ACLs for.
            is_directory (bool): Whether the path is a directory.
        Returns:
            AdlsPathAcl: Structured ACL information, or None on failure.
        """
        try:
            if is_directory:
                if path:
                    client = fs_client.get_directory_client(path)
                else:
                    client = fs_client._get_root_directory_client()
            else:
                client = fs_client.get_file_client(path)

            props = client.get_access_control()
            acl_string = props.get("acl", "")
            acl_entries = self.parse_acl_string(acl_string)

            return AdlsPathAcl(
                container=fs_client.file_system_name,
                path=path or "/",
                is_directory=is_directory,
                owner=props.get("owner", ""),
                group=props.get("group", ""),
                permissions=props.get("permissions", ""),
                acl_entries=acl_entries,
            )
        except Exception as exc:
            self.logger.warning(f"Could not read ACL for '{path or '/'}': {exc}")
            return None

    def __walk_path__(
        self, fs_client, path: str, max_depth: int, current_depth: int = 0
    ) -> List[AdlsPathAcl]:
        """
        Recursively collect ACLs for all directories/files under a path.
        Args:
            fs_client: The file system client for the container.
            path (str): The starting path.
            max_depth (int): Maximum recursion depth (-1 for unlimited).
            current_depth (int): Current recursion depth.
        Returns:
            List[AdlsPathAcl]: Collected ACL records.
        """
        results = []

        entry = self.__get_acl_for_path__(fs_client, path, is_directory=True)
        if entry:
            results.append(entry)

        if 0 <= max_depth <= current_depth:
            return results

        try:
            paths = fs_client.get_paths(path=path if path else "/", recursive=False)
            for p in paths:
                child = p.name
                if p.is_directory:
                    results.extend(
                        self.__walk_path__(fs_client, child, max_depth, current_depth + 1)
                    )
                else:
                    file_entry = self.__get_acl_for_path__(fs_client, child, is_directory=False)
                    if file_entry:
                        results.append(file_entry)
        except Exception as exc:
            self.logger.warning(f"Could not list paths under '{path or '/'}': {exc}")

        return results

    def __scan_containers__(
        self, container: Optional[str], path: str, max_depth: int
    ) -> List[AdlsPathAcl]:
        """
        Scan one or all containers and collect ACL entries.
        Args:
            container (str): Specific container to scan, or None for all.
            path (str): Starting path within the container.
            max_depth (int): Maximum recursion depth.
        Returns:
            List[AdlsPathAcl]: All collected ACL records.
        """
        results = []

        if container:
            containers = [container]
        else:
            containers = [fs.name for fs in self.service_client.list_file_systems()]

        for ctr in containers:
            self.logger.info(f"Scanning ADLS container: {ctr}")
            fs_client = self.service_client.get_file_system_client(ctr)
            results.extend(self.__walk_path__(fs_client, path, max_depth))

        return results

    @staticmethod
    def __extract_grants_from_acls__(path_acls: List[AdlsPathAcl]) -> List[AdlsGrant]:
        """
        Convert parsed ACL entries into normalised AdlsGrant objects.
        Only named user/group entries (those with an OID) are included.
        Args:
            path_acls (List[AdlsPathAcl]): Parsed path ACL records.
        Returns:
            List[AdlsGrant]: Normalised grant records.
        """
        grants = []
        for path_acl in path_acls:
            for entry in path_acl.acl_entries:
                if not entry.identifier:
                    continue
                if entry.type not in ("user", "group"):
                    continue

                grants.append(
                    AdlsGrant(
                        principal_id=entry.identifier,
                        principal_type=entry.type,
                        container=path_acl.container,
                        path=path_acl.path,
                        is_directory=path_acl.is_directory,
                        read=entry.read,
                        write=entry.write,
                        execute=entry.execute,
                        acl_scope=entry.scope,
                    )
                )

        return grants

    @staticmethod
    def __extract_unique_principals__(grants: List[AdlsGrant]) -> List[AdlsPrincipal]:
        """
        Extract unique principals from grants.
        Each principal is identified by its OID and type.
        Args:
            grants (List[AdlsGrant]): Grant records.
        Returns:
            List[AdlsPrincipal]: Unique principal records (unresolved — display_name/email empty).
        """
        seen = set()
        principals = []
        for grant in grants:
            key = (grant.principal_id, grant.principal_type)
            if key in seen:
                continue
            seen.add(key)
            principals.append(
                AdlsPrincipal(
                    object_id=grant.principal_id,
                    principal_type=grant.principal_type,
                )
            )
        return principals

    def __get_database_map__(
        self, source: Source, container: Optional[str] = None,
        path: str = "", max_depth: int = -1
    ) -> AdlsDatabaseMap:
        """
        Build the full ADLS database map by scanning ACLs and extracting grants.
        Analogous to SnowflakeAPIClient.__get_database_map__.
        Args:
            source (Source): The source configuration.
            container (str): Optional specific container.
            path (str): Starting path.
            max_depth (int): Max recursion depth.
        Returns:
            AdlsDatabaseMap: The complete ACL data map.
        """
        self.logger.info(f"Building ADLS database map for source: {source.name}")

        path_acls = self.__scan_containers__(container, path, max_depth)
        self.logger.info(f"Collected {len(path_acls)} ACL entries from ADLS.")

        grants = self.__extract_grants_from_acls__(path_acls)
        self.logger.info(f"Extracted {len(grants)} grants from ACL entries.")

        principals = self.__extract_unique_principals__(grants)
        self.logger.info(f"Found {len(principals)} unique principals in grants.")

        return AdlsDatabaseMap(
            path_acls=path_acls,
            grants=grants,
            principals=principals,
        )
