import re
import uuid

class Utils:
    """
    Utility class for common operations in the Policy Weaver application.
    This class provides static methods for validating email addresses and UUIDs.
    """

    @staticmethod
    def is_email(email):
        """
        Validate if the provided string is a valid email address.
        Args:
            email (str): The email address to validate.
        Returns:
            bool: True if the email is valid, False otherwise.
        """
        pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        return re.match(pattern, email)
    
    @staticmethod
    def is_uuid(uuid_string:str) -> bool:
        """
        Validate if the provided string is a valid UUID.
        Args:
            uuid_string (str): The UUID string to validate.
        Returns:
            bool: True if the string is a valid UUID, False otherwise.
        """
        if not uuid_string:
            return False
        
        try:
            uuid.UUID(uuid_string)
            return True
        except ValueError:
            return False