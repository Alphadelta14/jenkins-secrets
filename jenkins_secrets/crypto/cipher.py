
import base64
import struct

from Crypto.Cipher import AES

from jenkins_secrets.crypto.keys import get_key
from jenkins_secrets.crypto.pkcs import pkcs5_unpad


class InvalidPayload(RuntimeError):
    pass


class CipherV1(object):
    """Represents a Hudson Secret V1 cipher.

    IV state is not fully built until decryption time.
    """
    version = 1

    def __init__(self, secrets_dir='secrets'):
        self.secrets_dir = secrets_dir
        self.key = get_key(secrets_dir=secrets_dir)

    def decrypt64(self, value):
        """Decrypts a base64-encoded string.

        Args:
            value (str): base64-encoded string

        Returns:
            decrypted (bytes): decrypted string

        Raises:
            RuntimeError if decryption failed
        """
        return self.decrypt(base64.b64decode(value))

    def decrypt(self, payload):
        """Decrypts a raw payload.

        Args:
            payload (bytes): encrypted string

        Returns:
            decrypted (bytes): decrypted string

        Raises:
            RuntimeError if decryption failed
        """
        try:
            version, iv_len, enc_len = struct.unpack('>BII', payload[:9])
        except struct.error:
            raise InvalidPayload('Could not parse payload')
        if version != self.version:
            raise InvalidPayload('Invalid Payload Version')
        if len(payload) != 1+8+iv_len+enc_len:
            raise InvalidPayload('Invalid payload')

        ciph_iv = payload[9:9+iv_len]
        enc = payload[9+iv_len:]
        ciph = AES.new(self.key, AES.MODE_CBC, ciph_iv)
        return pkcs5_unpad(ciph.decrypt(enc))
