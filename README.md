### SimpleAES

AES-256 encryption and decryption in Python for mere mortals.

Here's how simple it is.

    >>> from SimpleAES import SimpleAES
    >>> key = 'Some arbitrary bytestring.'  # Store this somewhere safe
    >>> aes = SimpleAES(key)
    >>> ciphertext = aes.encrypt('My secret plaintext data')
    >>> ciphertext
    '\x18\x00\x00\x00\x00\x00\x00\x00\xaf\xbal\xa0\xb5\xa3\x18?\xc6\x13\xb3\x1bjS\xa6;\x80z\xca(\x8cls\n3&\xa3\x93\x86\xf4\xf6\x08\xe8y\x05V\xa7\xc2\x1d\x03G\xff\x9fS\x80\xf5\x1b\x05'
    >>> plaintext = aes.decrypt(ciphertext)
    >>> plaintext
    'My secret plaintext data'

You can use arbitrarily long keys.  Use a good random generator to generate
one and store it safe.

Cipher block length is not configurable.  It only uses AES-256.


### Installation

The usual stuff.

    $ pip install SimpleAES

