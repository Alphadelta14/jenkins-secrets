
import xml.etree.ElementTree as XML

from jenkins_secrets.crypto.cipher import CipherV1

CRED_XPATH = 'domainCredentialsMap/entry/java.util.concurrent.CopyOnWriteArrayList/*'


def el_to_dict(elem):
    """Creates a dict of tag=>text entries.

    Args:
        elem (XML.Element)

    Returns:
        dict where tags are the keys, and text are the values.
        This recurses for subelements.
    """
    res = {}
    for child in elem:
        if len(child):
            res[child.tag] = el_to_dict(child)
        else:
            res[child.tag] = child.text
    return res


class Credentials(object):
    """Provides an interface to the credentials.xml
    """
    def __init__(self, filename='credentials.xml', secrets_dir='secrets'):
        self.filename = filename
        self.secrets_dir = secrets_dir
        self.xml = XML.parse(filename)
        self._ciph = None

    def __iter__(self):
        return self.xml.iterfind(CRED_XPATH)

    def load_cipher(self):
        """Loads the cipher from the provided secrets.

        Returns:
            CipherV1
        """
        if self._ciph is None:
            self._ciph = CipherV1(self.secrets_dir)
        return self._ciph

    def decrypt_secret(self, value):
        """Decrypts a single secret value.

        Args:
            value (str): base64-encoded string wrapped in ``{}``

        Returns:
            Decrypted value
        """
        if not value.startswith('{') or not value.endswith('}'):
            return value
        ciph = self.load_cipher()
        try:
            return ciph.decrypt64(value[1:-1])
        except RuntimeError:
            # Failed to decrypt. Return original.
            return value

    def resolve_secrets(self, entry):
        """Decrypts secrets in-place.

        Args:
            entry (dict)
        """
        for key in entry:
            value = entry[key]
            if isinstance(value, dict):
                self.resolve_secrets(value)
            else:
                entry[key] = self.decrypt_secret(value)

    def get(self, credential_id):
        """Gets a credential entry by id.

        Args:
            credential_id (str)

        Returns:
            entry (dict)
        """
        for elem in self:
            id_el = elem.find('id')
            if id_el is not None:
                if id_el.text != credential_id:
                    continue
                entry = el_to_dict(elem)
                self.resolve_secrets(entry)
                return entry
