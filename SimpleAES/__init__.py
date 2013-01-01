import random
import struct
import base64
import hashlib
import warnings
from StringIO import StringIO
from Crypto.Cipher import AES
from .version import VERSION
from .exceptions import EncryptionError, DecryptionError

__title__ = 'SimpleAES'
__version__ = VERSION
__author__ = 'Vincent Driessen'
__license__ = 'BSD'
__copyright__ = 'Copyright 2012 Vincent Driessen'


def check_output(cmd, input_=None, *popenargs, **kwargs):
    """Custom variant of stdlib's check_output(), but with stdin feed support."""
    from subprocess import Popen, PIPE, CalledProcessError
    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    stdin = None
    if input_ is not None:
        stdin = PIPE
    process = Popen(stdout=PIPE, stdin=stdin, *((cmd,) + popenargs), **kwargs)
    output, unused_err = process.communicate(input_)
    retcode = process.poll()
    if retcode:
        raise CalledProcessError(retcode, ' '.join(cmd), output=output)
    return output


def _random_noise(len):
    return ''.join(chr(random.randint(0, 0xFF)) for i in range(len))


class SimpleAES(object):
    def __init__(self, password):
        # First, generate a fixed-length key of 32 bytes (for AES-256)
        self._password = password

    def encrypt(self, string):
        """Encrypts a string using AES-256."""
        try:
            envvar = hashlib.sha256(_random_noise(16)).hexdigest()
            ciphertext = check_output([
                'openssl', 'enc', '-e', '-aes-256-cbc', '-a',
                '-salt', '-pass', 'env:{0}'.format(envvar)],
                input_=string,
                env={envvar: self._password})
            return ciphertext.strip()
        except:
            raise EncryptionError('Could not encrypt.')

    def decrypt(self, b64_ciphertext, legacy='auto'):
        """Decrypts a string using AES-256."""
        if legacy is True or (legacy == 'auto' and
                              not b64_ciphertext.startswith('U2Fsd')):
            return self._legacy_decrypt(b64_ciphertext)

        try:
            envvar = hashlib.sha256(_random_noise(16)).hexdigest()
            plaintext = check_output([
                'openssl', 'enc', '-d', '-aes-256-cbc', '-a', '-pass',
                'env:{0}'.format(envvar)],
                input_=b64_ciphertext + '\n',
                env={envvar: self._password})
            return plaintext
        except:
            raise DecryptionError('Could not decrypt.')

    def _legacy_decrypt(self, b64_ciphertext):
        """Decrypts a string that's encoded with a SimpleAES version < 1.0.
        To convert a ciphertext to the new-style algo, use:

            aes = SimpleAES('my secret')
            aes.convert(legacy_ciphertext)
        """
        cipherbytes = base64.b64decode(b64_ciphertext)
        fin = StringIO(cipherbytes)
        fout = StringIO()

        key = hashlib.sha256(self._password).digest()
        chunksize = 64 * 1024
        try:
            input_size = struct.unpack('<Q', fin.read(struct.calcsize('Q')))[0]
            iv = fin.read(16)
            aes = AES.new(key, AES.MODE_CBC, iv)

            while True:
                chunk = fin.read(chunksize)
                if len(chunk) == 0:
                    break  # done
                fout.write(aes.decrypt(chunk))

            # truncate any padded random noise
            fout.truncate(input_size)

            text = fout.getvalue()
        finally:
            fin.close()
            fout.close()

        return text

    def base64_encrypt(self, string):
        # Since 1.0, encrypt returns the result base64-encoded already
        warnings.warn('base64_encrypt() is deprecated in favor of encrypt().',
                      DeprecationWarning)
        return self.encrypt(string)

    def base64_decrypt(self, ciphertext):
        # Since 1.0, decrypt will base64-decode the input already
        warnings.warn('base64_decrypt() is deprecated in favor of decrypt().',
                      DeprecationWarning)
        return self.decrypt(ciphertext)


__all__ = ['SimpleAES']

if __name__ == '__main__':
    key = 'Som3 r4nd0mly g3nera4ted k3y!'
    aes = SimpleAES(key)
    for input_len in range(0, 128):
        for times in range(0, 3):
            input = _random_noise(input_len)
            ciphertext = aes.encrypt(input)
            text = aes.decrypt(ciphertext)
            assert text == input
    print 'All OK'
