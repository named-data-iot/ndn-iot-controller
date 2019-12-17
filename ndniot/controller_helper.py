import subprocess
import base64
import logging
from Cryptodome.IO.PKCS8 import unwrap
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from ndn.encoding import parse_and_check_tl
from ndn.app_support.security_v2 import SafeBag, SecurityV2TypeNumber
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat

def get_prv_key_from_safe_bag(id_name):
    """
    Export the safebag with password 1234 using ndnsec-export command line tool.
    The function then parse the exported safe bag and return the private key bytes.

    :param id_name: the NDN identity name
    """
    p = subprocess.run(['ndnsec-export', id_name, '-P', '1234'], stdout=subprocess.PIPE)
    wire = base64.b64decode(p.stdout)
    logging.debug('result from ndnsec-export')
    logging.debug(wire)
    wire = parse_and_check_tl(wire, SecurityV2TypeNumber.SAFE_BAG)
    bag = SafeBag.parse(wire)
    # Don't use unwrap because the key returned is still in DER format
    #key = unwrap(bytes(bag.encrypted_key_bag), '1234')[1]
    privateKey = serialization.load_der_private_key(bytes(bag.encrypted_key_bag), password=b'1234', backend=default_backend())

    cert_prv_key_hex = unwrap(privateKey.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))[1].hex()[
                       14:78]
    cert_prv_key = bytes.fromhex(cert_prv_key_hex)
    logging.info("Private KEY:")
    logging.info(cert_prv_key_hex)

    return cert_prv_key


if __name__ == '__main__':
    get_prv_key_from_safe_bag('/example')