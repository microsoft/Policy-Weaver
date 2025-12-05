class PolicyWeaverError(Exception):
    """
    Custom exception for Policy Weaver errors.
    This exception can be raised for any errors specific to the Policy Weaver application.
    It can be used to differentiate between general exceptions and those specific to Policy Weaver.
    Attributes:
        message (str): The error message.
    """
    pass