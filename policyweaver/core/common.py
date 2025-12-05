from datetime import datetime
from typing import Dict
import os
import json
import logging

from policyweaver.models.export import PolicyExport
from policyweaver.models.config import SourceMap
from policyweaver.core.enum import PolicyWeaverConnectorType

class classproperty(property):
    """
    A class property decorator that allows you to define properties that can be accessed on the class itself.
    Usage:
        class MyClass:
            @classproperty
            def my_property(cls):
                return "This is a class property
    """
    def __get__(self, owner_self, owner_cls):
        """
        Get the value of the property.
        Args:
            owner_self: The owner self.
            owner_cls: The owner class.
        Returns:
            The value of the property.
        """
        return self.fget(owner_cls)

class PolicyWeaverCore:
    """
    Core class for Policy Weaver, responsible for mapping policies
    from various sources to a unified format.
    This class initializes with a connector type and configuration,
    and provides a method to map policies.
    Example usage:
        core = PolicyWeaverCore(PolicyWeaverConnectorType.AZURE, config)
        policy_export = core.map_policy()
    """
    def __init__(self, type: PolicyWeaverConnectorType, config:SourceMap):
        """
        Initialize the PolicyWeaverCore with a connector type and configuration.
        Args:
            type (PolicyWeaverConnectorType): The type of connector to use (e.g., Azure, AWS).
            config (SourceMap): Configuration settings for the policy mapping.
        """
        self.connector_type = type
        self.config = config
        self.logger = logging.getLogger("POLICY_WEAVER")

    def map_policy(self) -> PolicyExport:
        """
        Map policies from the configured source to a unified format.
        This method retrieves policies from the source, processes them,
        and returns a PolicyExport object containing the mapped policies.
        Returns:
            PolicyExport: An object containing the mapped policies.
        """
        pass

class SnapshotExport:
    """
    A class to handle the export of snapshots to a specified directory.
    This class provides methods to export snapshots for different types of sources
    (e.g., dbx, fabric) and unmapped snapshots.
    It creates directories for each type and saves the snapshots in JSON format.
    Example usage:
        snapshot_export = SnapshotExport(directory="/path/to/export")
        snapshot_export.dbx_export_snapshot(snapshot_data)
    """
    def __init__(self, directory:str = None):
        """
        Initialize the SnapshotExport with a directory to save snapshots.
        Args:
            directory (str): The directory where snapshots will be saved.
        If no directory is provided, it defaults to the current directory.
        """
        if not directory:
            self.directory = "."
        else:
            self.directory = directory

    def dbx_export_snapshot(self, snapshot:dict):
        """
        Export a snapshot for Databricks (dbx) to the specified directory.
        Args:
            snapshot (dict): The snapshot data to be exported.
            This method creates a directory for dbx snapshots if it doesn't exist
            and saves the snapshot in JSON format with a timestamped filename.
        """
        self.__write_to_log__("dbx", snapshot)
    
    def fabric_export_snapshot(self, snapshot:dict):
        """
        Export a snapshot for Fabric to the specified directory.
        Args:
            snapshot (dict): The snapshot data to be exported.
            This method creates a directory for fabric snapshots if it doesn't exist
            and saves the snapshot in JSON format with a timestamped filename.
        """
        self.__write_to_log__("fabric", snapshot)

    def unmapped_snapshot(self, snapshot:dict):
        """
        Export an unmapped snapshot to the specified directory.
        Args:
            snapshot (dict): The snapshot data to be exported.
            This method creates a directory for unmapped snapshots if it doesn't exist
            and saves the snapshot in JSON format with a timestamped filename.
        """
        self.__write_to_log__("unmapped", snapshot)

    def __write_to_log__(self, type: str, data: dict):
        """
        Write the snapshot data to a log file in the specified directory.
        Args:
            type (str): The type of snapshot (e.g., "dbx", "fabric", "unmapped").
            data (dict): The snapshot data to be written to the log file.
        This method creates a directory for the specified type if it doesn't exist
        and saves the snapshot in JSON format with a timestamped filename.
        """
        log_directory = f"{self.directory}/{type.lower()}_snapshot"

        os.makedirs(log_directory, exist_ok=True)

        log_file = f"{log_directory}/snapshot_{datetime.now().strftime('%Y_%m_%d_%H_%M_%S')}.json"

        with open(log_file, "w") as file:
            json.dump(data, file, indent=4)