## SimpleAES

[AES-256](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption
and decryption in Python for mere mortals.

AES is a _symmetric_ encryption algorithm, meaning you use the same key to
encrypt and decrypt the data later on.

Here's how simple it is:

```pycon
>>> from SimpleAES import SimpleAES
>>> key = 'Some arbitrary bytestring.'  # Store this somewhere safe
>>> aes = SimpleAES(key)
>>> ciphertext = aes.encrypt('My secret plaintext data')
>>> ciphertext
'U2FsdGVkX1/n2YDlhnMBHXxjyWT1fQ58lECKmC97Polz17mWCuLQmzJRzCtlWT29'
>>> plaintext = aes.decrypt(ciphertext)
>>> plaintext
'My secret plaintext data'
```


### Compatibility notes

**WARNING:** SimpleAES breaks compatibility with pre-1.0 releases.  
It does so for good reasons, namely exchangability.  Before 1.0, strings
encrypted with SimpleAES could only be decrypted with SimpleAES itself.  Since
version 1.0, it's possible to decrypt string like the above on the command
line, for example:

```console
$ echo 'U2FsdGVkX1/n2YDlhnMBHXxjyWT1fQ58lECKmC97Polz17mWCuLQmzJRzCtlWT29' | openssl enc -d -a -aes-256-cbc -pass pass:'Some arbitrary bytestring.'
My secret plaintext data
```

Also, it's possible to send this data to another process or language and
decrypt it there.  In short, the format is more standardized.

You can convert all of your encrypted keys to the new format by decrypting and
encrypting again with the same key.  Decryption will auto-detect the legacy
format and use the old decryption technique.

Example of converting legacy ciphertexts:

```pycon
>>> legacy_ciphertext = 'BAAAAAAAAABVCpqip59yhZE2zMmmhalthEsDnBaQ4XwAH4mkLL59kA=='
>>> aes.encrypt(aes.decrypt(legacy_ciphertext))
'U2FsdGVkX1/e8fspJOKoQLSejTumFj01YW1UgLPhrvAiM3A34bevVmmY7p+oNYOF\nwcpnPNmI6xyVKtjpVm+ElQ=='
```


### Details

You can use arbitrarily long keys.  Use a good random generator to generate one
and store it safe.

AES has a fixed block length (128 bits) and supports variable key sizes, but
this library always uses AES-256, meaning 256-bit key sizes.


### Be warned!

Only ever use this library for encrypting/decrypting relatively *small pieces
of text*.  It is not optimized for encrypting streams of data, only in-memory
strings.


## Installation

The usual stuff.

    $ pip install SimpleAES

