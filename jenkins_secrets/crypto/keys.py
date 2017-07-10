
import hashlib
import os

from Crypto.Cipher import AES

from jenkins_secrets.crypto.pkcs import pkcs5_unpad


def get_master_key(keyname='master.key', secrets_dir='secrets'):
    """Loads the master.key.

    Returns:
        16-byte (128-bit) AES key.
    """
    # Just because the master key is hex-encoded does not mean it should be decoded!
    with open(os.path.join(secrets_dir, keyname)) as handle:
        key = handle.read().strip()
    sha = hashlib.sha256()
    sha.update(key)
    return sha.digest()[:16]


def get_key(keyname='com.cloudbees.plugins.credentials.SecretBytes.KEY',
            secrets_dir='secrets'):
    """Reads a secret keyfile.

    Returns:
        16-byte (128-bit) AES key.
    """
    ciph = AES.new(get_master_key(secrets_dir=secrets_dir))
    with open(os.path.join(secrets_dir, keyname)) as handle:
        data = handle.read()
    value = pkcs5_unpad(ciph.decrypt(data))
    assert value.endswith('::::MAGIC::::')
    return value[:16]
