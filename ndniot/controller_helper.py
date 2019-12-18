import subprocess
import base64
import logging

from Cryptodome.PublicKey import ECC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from ndn.app_support.nfd_mgmt import parse_response, make_command, FaceQueryFilter, FaceQueryFilterValue, FaceStatusMsg
from ndn.app_support.security_v2 import SafeBag, SecurityV2TypeNumber
from ndn.types import InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError
from ndn.encoding import Component, Name, parse_and_check_tl


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
    ecc_key = ECC.import_key(privateKey.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
    logging.debug("pub key: ")
    logging.debug(ecc_key.pointQ.xy)
    logging.debug("prv key: ")
    logging.debug(ecc_key.d)
    cert_prv_key_hex = hex(ecc_key.d)[2:]
    cert_prv_key = bytes.fromhex(cert_prv_key_hex)
    logging.info("Private KEY:")
    logging.info(cert_prv_key_hex)
    return cert_prv_key


###################################
# NFD management helper functions #
###################################


async def query_face_id(app, uri):
    query_filter = FaceQueryFilter()
    query_filter.face_query_filter = FaceQueryFilterValue()
    query_filter.face_query_filter.uri = uri.encode('utf-8')
    query_filter_msg = query_filter.encode()
    name = Name.from_str("/localhost/nfd/faces/query") + [Component.from_bytes(query_filter_msg)]
    try:
        _, _, data = await app.express_interest(name, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
    except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
        logging.error(f'Query failed')
        return None
    ret = FaceStatusMsg.parse(data)
    logging.info(ret)
    return ret.face_status[0].face_id


async def add_route(app, name: str, face_id: int):
    interest = make_command('rib', 'register', name=name, face_id=face_id)
    try:
        _, _, data = await app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
    except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
        logging.error(f'Command failed')
        return False
    ret = parse_response(data)
    if ret['status_code'] <= 399:
        return True
    return False


async def remove_route(app, name: str, face_id: int):
    interest = make_command('rib', 'unregister', name=name, face_id=face_id)
    try:
        _, _, data = await app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
    except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
        logging.error(f'Command failed')
        return False
    ret = parse_response(data)
    if ret['status_code'] <= 399:
        return True
    return False


async def set_strategy(app, name: str, strategy: str):
    interest = make_command('strategy-choice', 'set', name=name, strategy=strategy)
    try:
        _, _, data = await app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
    except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
        logging.error(f'Command failed')
        return False
    ret = parse_response(data)
    if ret['status_code'] <= 399:
        return True
    return False


async def unset_strategy(app, name: str):
    interest = make_command('strategy-choice', 'unset', name=name)
    try:
        _, _, data = await app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
    except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
        logging.error(f'Command failed')
        return False
    ret = parse_response(data)
    if ret['status_code'] <= 399:
        return True
    return False


if __name__ == '__main__':
    get_prv_key_from_safe_bag('/example')