import asyncio
import logging
import plyvel
import struct
import time
from .ECDH import ECDH
from hashlib import sha256
from os import urandom
from Cryptodome.Cipher import AES
from base64 import b64encode
from .db_storage import *
from .tlvtree import TLVTree
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
from Cryptodome.IO.PKCS8 import wrap,unwrap
from ndn.encoding import Name, Component, InterestParam, BinaryStr, FormalName, MetaInfo
from ndn.app_support.nfd_mgmt import parse_response, make_command, FaceQueryFilter, FaceQueryFilterValue, FaceStatusMsg
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError
from ndn.security import KeychainSqlite3, Identity
from typing import Optional
from .ndn_security_sign_on import *
from ndn.security.signer import HmacSha256Signer
from ndn.app_support.security_v2 import parse_certificate

default_prefix = "/ndn-iot"
default_udp_multi_uri = "udp4://224.0.23.170:56363"
controller_port = 6363

class Controller:
    def __init__(self, emit_func):
        self.emit = emit_func
        self.running = True
        self.networking_ready = False
        self.listen_to_boot_request = False
        self.listen_to_cert_request = False
        self.boot_state = None

        self.app = NDNApp()
        self.system_prefix = None
        self.system_anchor = None
        self.db = None
        self.device_list = DeviceList()
        self.real_service_list = {}
        self.access_list = AccessList()
        self.shared_secret_list = SharedSecrets()

    def save_db(self):
        if self.db:
            wb = self.db.write_batch()
            wb.put(b'device_list', self.device_list.encode())
            wb.put(b'service_list', self.service_list.encode())
            wb.put(b'access_list', self.access_list.encode())
            wb.put(b'shared_secret_list',self.shared_secret_list.encode())
            wb.write()
            self.db.close()

    def system_init(self):
        logging.info("Server starts its initialization")
        # create or get existing state
        # Step One: Meta Info
        # 1. get system prefix from storage (from Level DB)
        import os
        db_dir = os.path.expanduser('~/.ndn-iot-controller/')
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.db = plyvel.DB(db_dir, create_if_missing=True)
        ret = self.db.get(b'system_prefix')
        if ret:
            self.system_prefix = ret.decode()
        else:
            self.system_prefix = default_prefix
            self.db.put(b'system_prefix', default_prefix.encode())
        # 2. get system root anchor certificate and private key (from keychain)
        anchor_key = KeychainSqlite3.new_key(id_name=self.system_prefix)
        self.system_anchor = anchor_key.default_cert()
        logging.info("Server finishes the step 1 initialization")

        # Step Two: App Layer Support (from Level DB)
        # 1. DEVICES: get all the certificates for devices from storage
        ret = self.db.get(b'device_list')
        if ret:
            self.device_list.parse(ret)
        # 2. SERVICES: get service list and corresponding providers
        ret = self.db.get(b'service_list')
        if ret:
            srv_lst = ServiceList()
            srv_lst.parse(ret)
            self.service_list = srv_lst
        # 3. ACCESS CONTROL: get all the encryption/decryption key pairs
        ret = self.db.get(b'access_list')
        if ret:
            self.access_list.parse(ret)
        # 4. SHARED SECRETS: get all shared secrets
        ret = self.db.get(b'shared_secret_list')
        if ret:
            self.shared_secret_list.parse(ret)
        logging.info("Server finishes the step 2 initialization")

    async def iot_connectivity_init(self):
        # Step Three: Configure Face and Route
        # 1. Find/create NFD's UDP Multicast Face, BLE Multicast Face, etc.
        face_id = await self.query_face_id(default_udp_multi_uri)
        logging.info("Found UDP multicast face {:d}".format(face_id))
        if face_id:
             # 2. Set up NFD's route from IoT system prefix to multicast faces
            ret = await self.add_route(self.system_prefix, face_id)
            if ret is True:
                logging.info("Successfully add route.")
            else:
                logging.fatal("Cannot set up the route for IoT prefix")
            # 3. Set up NFD's multicast strategy for IoT system namespace
            ret = await self.set_strategy(self.system_prefix, Name("/localhost/nfd/strategy/multicast"))
            if ret is True:
                self.networking_ready = True
                logging.info("Successfully add multicast strategy.")
                logging.info("Server finishes the step 3 initialization")
            else:
                logging.fatal("Cannot set up the strategy for IoT prefix")
        else:
            logging.fatal("Cannot find existing udp multicast face")

        @self.app.route('/ndn/sign-on')
        def on_sign_on_interest(self, name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            # TODO:Verifying the signature
            if not self.listen_to_boot_request:
                return
            self.process_sign_on_request(name, app_param)

        @self.app.route(self.system_prefix + '/cert')
        def on_cert_request_interest(self, name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            # TODO:Verifying the signature
            if not self.listen_to_cert_request:
                return
            self.HandleSignOnSecondInterest(name, app_param)

    def process_sign_on_request(self, name, app_param):
        logging.info("[SIGN ON]: interest received")
        logging.info(name)
        if not app_param:
            logging.error("[SIGN ON]: interest has no parameter")
            return
        state = {'DeviceIdentifier': None,
                  'DeviceCapability': None,
                  'N1PublicKey': None,
                  'N2PrivateKey':None,
                  'N2PublicKey':None,
                  'SharedKey':None,
                  'Salt':None,
                  'TrustAnchorDigest':None,
                  'SharedPublicKey':None,
                  'SharedSymmetricKey':None,
                  'DeviceIdentityName':None}
        registerID = -1
        request = SignOnRequest.parse(app_param)

        if not request.identifier or not request.capabilities or not request.ecdh_n1:
            logging.error("[SIGN ON]: lack parameters in application parameters")
            return
        state['DeviceIdentifier'] = request.identifier
        state['DeviceCapability'] = request.capabilities
        state['N1PublicKey'] = request.ecdh_n1

        found = False
        for ss in self.shared_secret_list.sharedsecrets:
            identifier_str = state["DeviceIdentifier"].decode('utf-8')
            if ss.device_identifier == identifier_str:
                state['SharedPublicKey'] = bytes.fromhex(ss.public_key)
                state['SharedSymmetricKey'] = bytes.fromhex(ss.symmetric_key)
                found = True
                break
        if not found:
            logging.error("[SIGN ON]: no preshared information about the device")
            return

        # TODO: check whether the device has already bootstrapped
        # TODO: Verify the signature:pre_installed_ecc_key
        shared_public_key = state['SharedPublicKey']

        trust_anchor_bytes = self.system_anchor
        logging.info(self.system_anchor)
        logging.info(trust_anchor_bytes)
        m = sha256()
        m.update(trust_anchor_bytes)
        state['TrustAnchorDigest'] = m.digest()
        # ECDH
        ecdh = ECDH()
        state['N2PrivateKey'] = ecdh.prv_key.to_string()
        state['N2PublicKey'] = ecdh.pub_key.to_string()
        # random 16 bytes for salt
        state['Salt'] = urandom(16)
        ecdh.encrypt(state['N1PublicKey'], state['Salt'])
        state['SharedKey'] = ecdh.derived_key

        response = SignOnResponse()
        response.salt = state['Salt']
        response.ecdh_n2 = state['N2PublicKey']
        response.anchor = self.system_anchor

        signer = HmacSha256Signer('pre-shared', state['SharedSymmetricKey'])
        self.app.put_data(name, response.encode(), freshness_period=3000, signer=signer)
        self.boot_state = state
        self.listen_to_cert_request = True

    def get_crypto_private_key(self,cert: CertificateV2):
        cert_safe_bag = self.keychain.exportSafeBag(cert, None)
        crypto_cert_prv_key = cert_safe_bag.getPrivateKeyBag()

        # Decode the PKCS #8 DER to find the algorithm OID.
        oidString = None
        try:
            parsedNode = DerNode.parse(crypto_cert_prv_key.buf())
            pkcs8Children = parsedNode.getChildren()
            algorithmIdChildren = DerNode.getSequence(
                pkcs8Children, 1).getChildren()
            oidString = "" + algorithmIdChildren[0].toVal()
        except Exception as ex:
            raise TpmPrivateKey.Error(
                "Cannot decode the PKCS #8 private key: " + str(ex))

        if oidString == TpmPrivateKey.EC_ENCRYPTION_OID:
            keyType = KeyType.EC
        elif oidString == TpmPrivateKey.RSA_ENCRYPTION_OID:
            keyType = KeyType.RSA
        else:
            raise TpmPrivateKey.Error(
                "loadPkcs8: Unrecognized private key OID: " + oidString)

        if keyType == KeyType.EC or keyType == KeyType.RSA:
            _privateKey = serialization.load_der_private_key(
                crypto_cert_prv_key.toBytes(), password=None, backend=default_backend())
        else:
            raise TpmPrivateKey.Error(
                "loadPkcs8: Unrecognized keyType: " + str(keyType))
        return _privateKey

    def decode_crypto_private_key(self,privateKey):
        cert_prv_key_hex = unwrap(privateKey.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))[1].hex()[14:78]
        cert_prv_key = bytes.fromhex(cert_prv_key_hex)
        logging.info("Private KEY:")
        logging.info(cert_prv_key_hex)
        return cert_prv_key

    def get_crypto_public_key(self,cert: CertificateV2):
        crypto_prv_key = self.get_crypto_private_key(cert)
        return crypto_prv_key.public_key()

    def decode_crypto_public_key(self,publicKey):
        cert_pub_key_hex = publicKey.public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo).hex()[-128:]
        cert_pub_key = bytes.fromhex(cert_pub_key_hex)
        logging.info("Public KEY:")
        logging.info(cert_pub_key_hex)
        return cert_pub_key


    def process_cert_request(self, name, app_param):
        logging.info("[CERT REQ]: interest received")
        logging.info(name)
        if not app_param:
            logging.error("[CERT REQ]: interest has no parameter")
            return
        request = CertRequest.parse(app_param)
        if not request.identifier or not request.ecdh_n2 or not request.anchor_digest or not request.ecdh_n1:
            raise KeyError("[CERT REQ]: lacking parameters in application parameters")
        logging.info(request.identifier)
        logging.info(request.ecdh_n2)
        logging.info(request.anchor_digest)
        logging.info(request.ecdh_n1)
        if request.identifier != self.boot_state['DeviceIdentifier'] or \
                request.ecdh_n2 != self.boot_state['N2PublicKey'] or \
                request.anchor_digest != self.boot_state['TrustAnchorDigest'] or \
                request.ecdh_n1 != self.boot_state['N1PublicKey']:
            logging.error("[CERT REQ]: unauthenticated request")
            return
        # anchor signed certificate
        # create identity and key for the device
        device_name = Name(self.system_prefix + '/' + request.identifier.decode('utf-8'))
        device_key = KeychainSqlite3.new_key(id_name=device_name)
        cert_bytes = device_key.default_cert()
        cert = parse_certificate(cert_bytes)
        private_key = self.decode_crypto_private_key(self.get_crypto_private_key(cert))

        # AES
        iv = urandom(16)
        cipher = AES.new(self.boot_state['SharedKey'], AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(private_key)
        logging.info('Symmetic Key')
        logging.info(self.boot_state['SharedKey'])
        # AES IV
        logging.info("IV:")
        logging.info(iv)
        # encrpted device private key with temporary symmetric key
        ct = b64encode(ct_bytes)
        logging.info("Cipher:")
        logging.info(ct)

        response = CertResponse()
        response.cipher = ct
        response.iv = iv
        response.id_cert = cert_bytes

        signer = HmacSha256Signer('pre-shared', self.boot_state['SharedSymmetricKey'])
        self.app.put_data(name, response.encode(), freshness_period=3000, signer=signer)

    async def bootstrapping(self):
        self.listen_to_boot_request = True
        result = {'DeviceIdentifier': None,
                  'DeviceCapability': None,
                  'N1PublicKey': None,
                  'N2PrivateKey': None,
                  'N2PublicKey': None,
                  'SharedKey': None,
                  'Salt': None,
                  'TrustAnchorDigest': None,
                  'SharedPublicKey': None,
                  'SharedSymmetricKey': None,
                  'DeviceIdentityName': None}
        #sign on
        ret = await self.on_sign_on_interest('/ndn/sign-on')
        if not ret:
            return {'st_code': 500}
        #certificate request
        ret = await self.on_certificate_request_interest(self.face,Name(self.system_prefix + '/cert'),ret)
        if not ret:
            return {'st_code': 500}
        new_device = self.device_list.device.add()
        new_device.device_id = ret["DeviceIdentifier"]
        new_device.device_info = ret["DeviceCapability"]
        new_device.device_cert_name = ret["DeviceIdentityName"]
        return {'st_code':200,'device_id': ret['DeviceIdentifier'].decode('utf-8')}


    def get_access_status(self, parameter_list):
        pass

    def invoke_service(self, parameter_list):
        pass

    async def query_face_id(self, uri):
        query_filter = FaceQueryFilter()
        query_filter.face_query_filter = FaceQueryFilterValue()
        query_filter.face_query_filter.uri = uri.encode('utf-8')
        query_filter_msg = query_filter.encode()
        name = Name.from_str("/localhost/nfd/faces/query") + [Component.from_bytes(query_filter_msg)]
        try:
            _, _, data = await self.app.express_interest(
                name, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Query failed')
            return None
        msg = FaceStatusMsg.parse(data)
        if len(msg.face_status) <= 0:
            return None
        return msg.face_status[0].face_id

    async def add_route(self, name: str, face_id: int):
        interest = make_command('rib', 'register', name=name, face_id=face_id)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        ret['status_code'] = ret['state_code'].decode()
        if ret['status_code'] <= 399:
            return True
        return False

    async def remove_route(self, name: str, face_id: int):
        interest = self.make_command('rib', 'unregister', name=name, face_id=face_id)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        ret['status_code'] = ret['state_code'].decode()
        if ret['status_code'] <= 399:
            return True
        return False

    async def set_strategy(self, name: str, strategy: str):
        interest = self.make_command('strategy-choice', 'set', name=name, strategy=strategy)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        ret['status_code'] = ret['state_code'].decode()
        if ret['status_code'] <= 399:
            return True
        return False

    async def unset_strategy(self, name: str):
        interest = self.make_command('strategy-choice', 'unset', name=name)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        ret['status_code'] = ret['state_code'].decode()
        if ret['status_code'] <= 399:
            return True
        return False

    async def run(self):
        logging.info("Restarting app...")
        while True:
            try:
                await self.app.main_loop(self.face_event())
            except KeyboardInterrupt:
                logging.info('Receiving Ctrl+C, shutdown')
                break
            except (FileNotFoundError, ConnectionRefusedError):
                logging.info("NFD disconnected...")
            finally:
                self.app.shutdown()
            await asyncio.sleep(3.0)

    ###################
    @staticmethod
    def get_time_now_ms():
        return round(time.time() * 1000.0)

    def on_sd_adv_interest(self, _prefix, interest: Interest, _face, _filter_id, interest_filter: InterestFilter):
        param = interest.applicationParameters.toBytes()
        # prefix = /<home-prefix>/<SD=1>/<ADV=0>
        locator = interest.name.getSubName(interest_filter.getPrefix().size())
        locator = locator[:-1]  # Remove parameter digest
        fresh_period = struct.unpack("!I", param[:4])[0]
        service_ids = [sid for sid in param[4:]]
        logging.debug("ON ADV: %s %s %s", locator, fresh_period, service_ids)
        cur_time = self.get_time_now_ms()
        for sid in service_ids:
            # /<home-prefix>/<SD=1>/<service>/<locator>
            sname = (Name(self.system_prefix)
                     .append(Name.Component.fromNumber(1))
                     .append(Name.Component.fromNumber(sid))
                     .append(locator))
            logging.debug("SNAME: %s", sname)
            self.real_service_list[sname.toUri()] = cur_time + fresh_period

    def on_sd_ctl_interest(self, _prefix, interest: Interest, face: Face, _filter_id, _interest_filter):
        logging.info("SD : on interest")
        param = interest.applicationParameters.toBytes()
        if param is None:
            logging.error("Malformed Interest")
            return
        interested_ids = {sid for sid in param}
        result = b''
        cur_time = self.get_time_now_ms()
        for sname, exp_time in self.real_service_list.items():
            sid = Name(sname)[2].toNumber()
            if sid in interested_ids and exp_time > cur_time:
                result += Name(sname).wireEncode().toBytes()
                result += struct.pack("i", exp_time - cur_time)

        data = Data(interest.name)
        data.content = result
        data.metaInfo.freshnessPeriod = 5000
        face.putData(data)
        logging.debug("PutData %s", data.name.toUri())

    def on_register_failed(self, prefix):
        logging.fatal("Prefix registration failed: %s", prefix)

    def setup_sd(self):
        # /<home-prefix>/<SD=1>
        sd_prefix = Name(self.system_prefix).append(Name.Component.fromNumber(1))
        self.face.registerPrefix(sd_prefix, None, self.on_register_failed)
        # /<home-prefix>/<SD=1>/<SD_ADV=0>
        self.face.setInterestFilter(Name(sd_prefix).append(Name.Component.fromNumber(0)), self.on_sd_adv_interest)
        # /<home-prefix>/<SD_CTL=2>
        sd_ctl_prefix = Name(self.system_prefix).append(Name.Component.fromNumber(2))
        self.face.registerPrefix(sd_ctl_prefix, None, self.on_register_failed)
        # /<home-prefix>/<SD_CTL=2>/<SD_CTL_META=0>
        self.face.setInterestFilter(Name(sd_ctl_prefix).append(Name.Component.fromNumber(0)), self.on_sd_ctl_interest)

    def get_service_list(self):
        ret = ServiceList()
        for sname, exp_time in self.real_service_list.items():
            item = ServiceItem()
            item.service_id = Name(sname)[2].toNumber()
            item.service_name = sname
            item.exp_time = exp_time
            ret.service.append(item)
        return ret

    def set_service_list(self, srv_lst):
        self.real_service_list = {}
        cur_time = self.get_time_now_ms()
        for item in srv_lst.service:
            if item.exp_time > cur_time:
                self.real_service_list[item.service_name] = item.exp_time

    service_list = property(get_service_list, set_service_list)
