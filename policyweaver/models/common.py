from typing import Any
from pydantic import BaseModel, ConfigDict

import hashlib
import json

class CommonBaseModel(BaseModel):
    """
    Base model for all common models in the Policy Weaver application.
    This model provides common functionality such as alias handling and JSON serialization.
    Attributes:
        model_config (ConfigDict): Configuration for the model.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        exclude_unset=True,
        exclude_none=True,
    )

    @property
    def hash_sha256(self):
        """
        Computes the SHA-256 hash of the model's JSON representation.
        This is useful for generating a unique identifier for the model based on its content.
        Returns:
            str: The SHA-256 hash of the model's JSON representation.
        """
        data = json.dumps(self.model_dump_json(exclude_none=True, exclude_unset=True), sort_keys=True)
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def model_dump(self, **kwargs) -> dict[str, Any]:
        """
        Dumps the model to a dictionary, using aliases for field names.
        Args:
            **kwargs: Additional keyword arguments to pass to the model dump.
        Returns:
            dict[str, Any]: The model data as a dictionary with aliases.
        """
        return super().model_dump(by_alias=True, **kwargs)

    def model_dump_json(self, **kwargs) -> dict[str, Any]:
        """
        Dumps the model to a JSON string, using aliases for field names.
        Args:
            **kwargs: Additional keyword arguments to pass to the model dump.
        Returns:
            dict[str, Any]: The model data as a JSON string with aliases.
        """
        return super().model_dump_json(by_alias=True, **kwargs)

    def __getattr__(self, item):
        """
        Custom __getattr__ method to handle field aliases.
        This allows accessing model fields using their aliases.
        Args:
            item (str): The name of the attribute to access.
        Returns:
            Any: The value of the attribute if it exists, otherwise raises AttributeError.
        """
        for field, meta in self.model_fields.items():
            if meta.alias == item:
                return getattr(self, field)
        return super().__getattr__(item)

    def _get_alias(self, item_name):
        """
        Get the alias for a given item name.
        Args:
            item_name (str): The name of the item to get the alias for.
        Returns:
            str: The alias for the item if it exists, otherwise None.
        """
        for field, meta in self.model_fields.items():
            if field == item_name:
                return meta.alias

        return None