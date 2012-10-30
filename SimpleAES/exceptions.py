class SimpleAESError(Exception):
    pass


class EncryptionError(SimpleAESError):
    pass


class DecryptionError(SimpleAESError):
    pass
