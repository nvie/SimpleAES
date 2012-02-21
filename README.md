## SimpleAES

[AES-256](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption
and decryption in Python for mere mortals.

AES is a _symmetric_ encryption algorithm, meaning you use the same key to
encrypt and decrypt the data later on.

Here's how simple it is:

    >>> from SimpleAES import SimpleAES
    >>> key = 'Some arbitrary bytestring.'  # Store this somewhere safe
    >>> aes = SimpleAES(key)
    >>> ciphertext = aes.encrypt('My secret plaintext data')
    >>> ciphertext
    '\x18\x00\x00\x00\x00\x00\x00\x00\xaf\xbal\xa0\xb5\xa3\x18?\xc6\x13\xb3\x1bjS\xa6;\x80z\xca(\x8cls\n3&\xa3\x93\x86\xf4\xf6\x08\xe8y\x05V\xa7\xc2\x1d\x03G\xff\x9fS\x80\xf5\x1b\x05'
    >>> plaintext = aes.decrypt(ciphertext)
    >>> plaintext
    'My secret plaintext data'


### Details

You can use arbitrarily long keys.  Use a good random generator to generate one
and store it safe.  _(For the technically inclined: a 256-bit hash is calculated
from the input key and forms the actual encryption key.)_

AES has a fixed block length (128 bits) and supports variable key sizes, but
this library always uses AES-256, meaning 256-bit key sizes.


### Be warned!

Only every use this library for encrypting/decrypting relatively *small pieces
of text* (compared to available memory, that is).  It holds both the input and
output strings in memory for the full length of the algorithm, so memory peaks
may be an issue when used on large input strings.


## Installation

The usual stuff.

    $ pip install SimpleAES

