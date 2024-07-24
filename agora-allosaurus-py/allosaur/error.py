from enum import IntEnum

class AllosaurErrorCode(IntEnum):
    SUCCESS = 0
    INPUT = 1
    SIGNING = 2
    WRAPPER = 99

class AllosaurError(Exception):
    def __init__(self, code: AllosaurErrorCode, message: str, extra: str = None):
        super().__init__(message)
        self.code = code
        self.extra = extra