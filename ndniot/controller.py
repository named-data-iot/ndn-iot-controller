import asyncio
import logging
import plyvel
import struct
import time
from .ECDH import ECDH
from hashlib import sha256
from os import urandom
from random import SystemRandom
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import DSS
from .db_storage import *
from ndn.encoding import Component, InterestParam, BinaryStr, FormalName, Name, SignaturePtrs, SignatureType
from ndn.app_support.nfd_mgmt import parse_response, make_command, FaceQueryFilter, FaceQueryFilterValue, FaceStatusMsg
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError
from typing import Optional
from ndn.security.signer import HmacSha256Signer
from ndn.app_support.security_v2 import parse_certificate
from .controller_helper import *
from .ndn_security_sign_on import *

default_prefix = "ndn-iot"
default_udp_multi_uri = "udp4://224.0.23.170:56363"
controller_port = 6363

class Controller:
    """
    NDN IoT Controller.

    :ivar app: the python-ndn app
    :ivar system_prefix: a string representing the home namespace
    :ivar system_anchor: a TLV format NDN certificate
    :ivar db: the database handler
    :ivar device_list: the list of device
    :ivar access_list: the list of access rights
    :ivar shared_secret_list: the list of already-shared secrets
    """

    def __init__(self, emit_func):
        self.emit = emit_func
        self.running = True
        self.networking_ready = False
        self.listen_to_boot_request = False
        self.listen_to_cert_request = False
        self.boot_state = None
        self.boot_event = None

        self.app = NDNApp()
        self.system_prefix = None
        self.system_anchor = None
        self.db = None
        self.device_list = DeviceList()
        self.service_list = ServiceList()
        self.access_list = AccessList()
        self.shared_secret_list = SharedSecrets()

    def save_db(self):
        """
        Save the state into the database.
        """
        logging.debug('Save state to DB')
        if self.db:
            wb = self.db.write_batch()
            logging.debug(self.shared_secret_list.encode())
            wb.put(b'device_list', self.device_list.encode())
            wb.put(b'service_list', self.service_list.encode())
            wb.put(b'access_list', self.access_list.encode())
            wb.put(b'shared_secret_list', self.shared_secret_list.encode())
            wb.write()
            self.db.close()

    def system_init(self):
        """
        Init the system in terms of:
        Step 1: Create/load system prefix and system anchor from the storage if any
        Step 2: Create/load device list, service list, access rights, and shared secrets from the storage
        """

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
            logging.info('Found system prefix from db')
            self.system_prefix = ret.decode()
        else:
            self.system_prefix = default_prefix
            self.db.put(b'system_prefix', default_prefix.encode())
        # 2. get system root anchor certificate and private key (from keychain)
        anchor_identity = self.app.keychain.touch_identity(self.system_prefix)
        anchor_key = anchor_identity.default_key()
        self.system_anchor = anchor_key.default_cert().data
        logging.info("Server finishes the step 1 initialization")

        # Step Two: App Layer Support (from Level DB)
        # 1. DEVICES: get all the certificates for devices from storage
        ret = self.db.get(b'device_list')
        if ret:
            logging.info('Found device list from db')
            self.device_list = DeviceList.parse(ret)
        # 2. SERVICES: get service list and corresponding providers
        ret = self.db.get(b'service_list')
        if ret:
            logging.info('Found service list from db')
            self.service_list = ServiceList.parse(ret)
        # 3. ACCESS CONTROL: get all the encryption/decryption key pairs
        ret = self.db.get(b'access_list')
        if ret:
            logging.info('Found access list from db')
            self.access_list = AccessList.parse(ret)
        # 4. SHARED SECRETS: get all shared secrets
        ret = self.db.get(b'shared_secret_list')
        if ret:
            logging.info('Found shared secret from db')
            self.shared_secret_list = SharedSecrets.parse(ret)
        logging.info("Server finishes the step 2 initialization")

    async def iot_connectivity_init(self):
        """
        Init the system in terms of:
        Step 3: Configure network interface, forwarding strategy, and route
        """

        # Step Three: Configure Face and Route
        # 1. Find/create NFD's UDP Multicast Face, BLE Multicast Face, etc.
        face_id = await self.query_face_id(default_udp_multi_uri)
        if not face_id:
            logging.fatal("Cannot find existing udp multicast face")
            return
        logging.info("Successfully found UDP multicast face: %d", face_id)
        # 2. Set up NFD's route from IoT system prefix to multicast faces
        ret = await self.add_route(self.system_prefix, face_id)
        if ret is True:
            logging.info("Successfully add route.")
        else:
            logging.fatal("Cannot set up the route for IoT prefix")
        # 3. Set up NFD's multicast strategy for IoT system namespace
        ret = await self.set_strategy(self.system_prefix, "/localhost/nfd/strategy/multicast")
        if ret is True:
            self.networking_ready = True
            logging.info("Successfully add multicast strategy.")
            logging.info("Server finishes the step 3 initialization")
        else:
            logging.fatal("Cannot set up the strategy for IoT prefix")

        @self.app.route('/ndn/sign-on')
        def on_sign_on_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a security bootstrapping request

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters

            TODO:Verifying the signature
            """
            if not self.listen_to_boot_request:
                return
            self.process_sign_on_request(name, app_param)

        await asyncio.sleep(0.1)

        @self.app.route(self.system_prefix + '/cert')
        def on_cert_request_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is a certificate request during bootstrapping

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters

            TODO:Verifying the signature
            """
            if not self.listen_to_cert_request:
                return
            self.process_cert_request(name, app_param)

        await asyncio.sleep(0.1)

        @self.app.route([self.system_prefix, bytearray(b'\x08\x01\x01'), bytearray(b'\x08\x01\x00')], validator=self.verify_device_signature)
        def on_sd_adv_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when there is an service advertisement

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters

            Packet format: prefix = /<home-prefix>/<SD=1>/<ADV=0>/device-id
            App Parameter format:
            TODO:Verifying the signature
            """
            locator = name[3:-1]
            logging.debug("Adv Interest sender locator: ")
            logging.debug(locator)
            fresh_period = struct.unpack("!I", app_param[:4])[0]
            logging.debug("Adv Interest freshness: ")
            logging.debug(fresh_period)
            service_ids = [sid for sid in app_param[4:]]
            logging.debug('service ids')
            logging.debug(service_ids)
            cur_time = self.get_time_now_ms()
            for sid in service_ids:
                # Name format: /<home-prefix>/<service>/<locator>
                sname = [self.system_prefix, b'\x08\x01' + bytes([sid])] + locator
                sname = Name.to_str(sname)
                logging.debug('Service Name: ')
                logging.debug(sname)

                already_added = False
                for item in self.service_list.services:
                    if Name.to_str(item.service_name) == sname:
                        already_added = True
                        item.exp_time = cur_time + fresh_period
                if not already_added:
                    service = ServiceItem()
                    service.service_name = sname
                    service.exp_time = cur_time + fresh_period
                    service.service_id = sid
                    logging.debug('Add new service into the service list')
                    self.service_list.services.append(service)

        await asyncio.sleep(0.1)

        @self.app.route([self.system_prefix, bytearray(b'\x08\x01\x02'), bytearray(b'\x08\x01\x00')], validator=self.verify_device_signature)
        def on_sd_ctl_interest(name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]):
            """
            OnInterest callback when device want to query the existing services in the system

            :param name: Interest packet name
            :param param: Interest parameters
            :app_param: Interest application paramters
            TODO:Verifying the signature
            """
            logging.info("SD : on interest")
            if app_param is None:
                logging.error("Malformed Interest")
                return
            interested_ids = {sid for sid in app_param}
            result = b''
            cur_time = self.get_time_now_ms()
            for sname, exp_time in self.real_service_list.items():
                sid = sname[2][2]
                if sid in interested_ids and exp_time > cur_time:
                    result += Name.encode(sname)
                    result += struct.pack("i", exp_time - cur_time)

            self.app.put_data(name, result, freshness_period=3000, identity=self.system_prefix)
            logging.debug("PutData")
            logging.debug(name)

    def process_sign_on_request(self, name, app_param):
        """
        Process device's sign on request.

        :param name: Interest packet name
        :param app_param: Interest application parameters
        """
        logging.info("[SIGN ON]: interest received")
        if not app_param:
            logging.error("[SIGN ON]: interest has no parameter")
            return
        request = SignOnRequest.parse(app_param)

        if not request.identifier or not request.capabilities or not request.ecdh_n1:
            logging.error("[SIGN ON]: lack parameters in application parameters")
            return
        self.boot_state['DeviceIdentifier'] = bytes(request.identifier)
        self.boot_state['DeviceCapability'] = bytes(request.capabilities)
        self.boot_state['N1PublicKey'] = bytes(request.ecdh_n1)
        logging.info(self.boot_state)

        shared_secret = None
        for ss in self.shared_secret_list.shared_secrets:
            if bytes(ss.device_identifier) == bytes(request.identifier):
                shared_secret = ss
                break
        if not shared_secret:
            logging.error("[SIGN ON]: no pre-shared information about the device")
            return

        self.boot_state['SharedPublicKey'] = bytes.fromhex(bytes(shared_secret.public_key).decode())
        self.boot_state['SharedSymmetricKey'] = bytes.fromhex(bytes(shared_secret.symmetric_key).decode())

        # TODO: check whether the device has already bootstrapped
        # TODO: Verify the signature:pre_installed_ecc_key
        logging.info(self.system_anchor)
        m = sha256()
        m.update(self.system_anchor)
        self.boot_state['TrustAnchorDigest'] = m.digest()
        # ECDH
        ecdh = ECDH()
        self.boot_state['N2PrivateKey'] = ecdh.prv_key.to_string()
        self.boot_state['N2PublicKey'] = ecdh.pub_key.to_string()
        # random 16 bytes for salt
        self.boot_state['Salt'] = urandom(16)
        ecdh.encrypt(self.boot_state['N1PublicKey'], self.boot_state['Salt'])
        self.boot_state['SharedKey'] = ecdh.derived_key

        response = SignOnResponse()
        response.salt = self.boot_state['Salt']
        response.ecdh_n2 = self.boot_state['N2PublicKey']
        cert_bytes = parse_and_check_tl(self.system_anchor, TypeNumber.DATA)
        response.anchor = cert_bytes

        logging.info(response.encode())

        signer = HmacSha256Signer('pre-shared', self.boot_state['SharedSymmetricKey'])
        self.app.put_data(name, response.encode(), freshness_period=3000, signer=signer)
        self.listen_to_cert_request = True

    def process_cert_request(self, name, app_param):
        logging.info("[CERT REQ]: interest received")
        logging.info(name)
        if not app_param:
            logging.error("[CERT REQ]: interest has no parameter")
            return
        request = CertRequest.parse(app_param)
        if not request.identifier or not request.ecdh_n2 or not request.anchor_digest or not request.ecdh_n1:
            raise KeyError("[CERT REQ]: lacking parameters in application parameters")
        logging.info(bytes(request.identifier))
        logging.info(bytes(request.ecdh_n2))
        logging.info(bytes(request.anchor_digest))
        logging.info(bytes(request.ecdh_n1))
        if bytes(request.identifier) != self.boot_state['DeviceIdentifier'] or \
                bytes(request.ecdh_n2) != self.boot_state['N2PublicKey'] or \
                bytes(request.anchor_digest) != self.boot_state['TrustAnchorDigest'] or \
                bytes(request.ecdh_n1) != self.boot_state['N1PublicKey']:
            logging.error("[CERT REQ]: unauthenticated request")
            return
        # anchor signed certificate
        # create identity and key for the device
        # TODO Remove hardcoded livingroom and ask user for which room the device belongs to
        device_name = '/' + self.system_prefix + '/livingroom' + '/' + bytes(request.identifier).decode()
        device_key = self.app.keychain.touch_identity(device_name).default_key()
        private_key = get_prv_key_from_safe_bag(device_name)
        default_cert = device_key.default_cert().data
        # re-sign certificate using anchor's key
        cert = parse_certificate(default_cert)
        new_cert_name = cert.name[:-2]
        logging.debug(new_cert_name)
        new_cert_name.append('home')
        new_cert_name.append(Name.Component.from_version(SystemRandom().randint(10000000, 99999999)))
        logging.debug(new_cert_name)
        cert = self.app.prepare_data(new_cert_name, cert.content, identity=self.system_prefix)
        # AES
        iv = urandom(16)
        cipher = AES.new(self.boot_state['SharedKey'], AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(private_key)
        logging.info('raw private key')
        logging.info(private_key)
        logging.info('Symmetic Key')
        logging.info(self.boot_state['SharedKey'])
        # AES IV
        logging.info("IV:")
        logging.info(iv)
        logging.info("Cipher:")
        logging.info(ct_bytes)
        logging.info('Cipher length: ' + str(len(ct_bytes)))
        # encrpted device private key with temporary symmetric key
        #ct = b64encode(ct_bytes)

        response = CertResponse()
        response.cipher = ct_bytes
        response.iv = iv
        cert_bytes = parse_and_check_tl(cert, TypeNumber.DATA)
        response.id_cert = cert_bytes

        signer = HmacSha256Signer('pre-shared', self.boot_state['SharedSymmetricKey'])
        self.app.put_data(name, response.encode(), freshness_period=3000, signer=signer)
        self.boot_state["DeviceIdentityName"] = device_name
        self.boot_state['Success'] = True
        self.boot_event.set()

    async def bootstrapping(self):
        self.boot_state = {'DeviceIdentifier': None,
                           'DeviceCapability': None,
                           'N1PublicKey': None,
                           'N2PrivateKey': None,
                           'N2PublicKey': None,
                           'SharedKey': None,
                           'Salt': None,
                           'TrustAnchorDigest': None,
                           'SharedPublicKey': None,
                           'SharedSymmetricKey': None,
                           'DeviceIdentityName': None,
                           'Success': False}
        self.boot_event = asyncio.Event()
        self.listen_to_boot_request = True
        try:
            await asyncio.wait_for(self.boot_event.wait(), timeout=8.0)
        except asyncio.TimeoutError:
            self.boot_event.set()
        self.boot_event = None
        self.listen_to_boot_request = False
        self.listen_to_cert_request = False
        if self.boot_state['Success']:
            new_device = DeviceItem()
            new_device.device_id = self.boot_state["DeviceIdentifier"]
            new_device.device_info = self.boot_state["DeviceCapability"]
            new_device.device_identity_name = self.boot_state["DeviceIdentityName"]
            self.device_list.devices.append(new_device)
            return {'st_code':200, 'device_id': self.boot_state['DeviceIdentityName']}
        return {'st_code': 500}

    def get_access_status(self, parameter_list):
        pass

    def invoke_service(self, parameter_list):
        pass

    async def verify_device_signature(self, name: FormalName, sig: SignaturePtrs) -> bool:
        sig_info = sig.signature_info
        covered_part = sig.signature_covered_part
        sig_value = sig.signature_value_buf
        if not sig_info or sig_info.signature_type != SignatureType.SHA256_WITH_ECDSA:
            return False

        if not covered_part or not sig_value:
            return False
        identity = [sig_info.key_locator.name[0]] + sig_info.key_locator.name[-4:-2]
        logging.debug('Extract identity id from key id')
        logging.debug(Name.to_str(identity))
        key_bits = None
        try:
            key_bits = self.app.keychain.get(identity).default_key().key_bits
        except KeyError:
            logging.error('Cannot find pub key from keychain')
        pk = ECC.import_key(key_bits)
        verifier = DSS.new(pk, 'fips-186-3', 'der')
        hash = SHA256.new()
        for blk in covered_part:
            hash.update(blk)
        logging.debug(bytes(sig_value))
        logging.debug(len(bytes(sig_value)))
        try:
            verifier.verify(hash, bytes(sig_value))
        except ValueError:
            return False
        return True

    async def query_face_id(self, uri):
        query_filter = FaceQueryFilter()
        query_filter.face_query_filter = FaceQueryFilterValue()
        query_filter.face_query_filter.uri = uri.encode('utf-8')
        query_filter_msg = query_filter.encode()
        name = Name.from_str("/localhost/nfd/faces/query") + [Component.from_bytes(query_filter_msg)]
        try:
            _, _, data = await self.app.express_interest(name, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
             logging.error(f'Query failed')
             return None
        ret = FaceStatusMsg.parse(data)
        logging.info(ret)
        return ret.face_status[0].face_id

    async def add_route(self, name: str, face_id: int):
        interest = make_command('rib', 'register', name=name, face_id=face_id)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        if ret['status_code'] <= 399:
            return True
        return False

    async def remove_route(self, name: str, face_id: int):
        interest = make_command('rib', 'unregister', name=name, face_id=face_id)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        if ret['status_code'] <= 399:
            return True
        return False

    async def set_strategy(self, name: str, strategy: str):
        interest = make_command('strategy-choice', 'set', name=name, strategy=strategy)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        if ret['status_code'] <= 399:
            return True
        return False

    async def unset_strategy(self, name: str):
        interest = make_command('strategy-choice', 'unset', name=name)
        try:
            _, _, data = await self.app.express_interest(interest, lifetime=1000, can_be_prefix=True, must_be_fresh=True)
        except (InterestCanceled, InterestTimeout, InterestNack, ValidationFailure, NetworkError):
            logging.error(f'Command failed')
            return False
        ret = parse_response(data)
        if ret['status_code'] <= 399:
            return True
        return False

    async def run(self):
        logging.info("Restarting app...")
        while True:
            try:
                await self.app.main_loop(self.iot_connectivity_init())
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