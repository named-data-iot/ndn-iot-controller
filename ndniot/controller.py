import asyncio
import logging
import threading
import plyvel
import struct
import time
from pyndn import Face, Interest, Data, Name, NetworkNack, InterestFilter,KeyLocatorType
from pyndn.security import KeyChain, Pib
from pyndn.encoding import ProtobufTlv
from pyndn.encoding.tlv.tlv_encoder import TlvEncoder
import pyndn.transport
from pyndn.transport.unix_transport import UnixTransport
from pyndn.security.pib.pib_identity import PibIdentity
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.certificate_v2 import CertificateV2
from pyndn.security.key_params import EcKeyParams
from .asyncndn import fetch_data_packet,\
    decode_dict, decode_list, decode_name, decode_content_type, decode_nack_reason, connection_test
from .nfd_face_mgmt_pb2 import ControlCommandMessage, ControlResponseMessage, CreateFaceResponse, \
    FaceQueryFilterMessage, FaceStatusMessage
from .tlvtree import TLVTree
from .ECDH import ECDH
from .db_storage_pb2 import DeviceList, ServiceList, AccessList, SharedSecrets, ServiceItem
from hashlib import sha256
from os import urandom
from Crypto.Cipher import AES
from base64 import b64encode
from pyndn.util import Blob
from pyndn.hmac_with_sha256_signature import HmacWithSha256Signature
from ecdsa import SigningKey, VerifyingKey, NIST192p,NIST256p
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat
from pyndn.security.key_params import EcKeyParams
from Crypto.IO.PKCS8 import wrap,unwrap
from pyndn.encoding.der import DerNode
from pyndn.security.security_types import KeyType
from pyndn.security.tpm.tpm_private_key import TpmPrivateKey








default_prefix = "/ndn-iot"
default_udp_multi_uri = "udp4://224.0.23.170:56363"
controller_port = 6363

class Controller:
    def __init__(self, emit_func):
        self.running = True
        self.networking_ready = False
        self.emit = emit_func
        self.keychain = KeyChain('pib-memory','tpm-memory')
        self.face = None

        self.system_prefix = None
        self.system_anchor = None
        self.db = None
        self.device_list = DeviceList()
        # self.service_list = ServiceList()
        self.real_service_list = {}
        self.access_list = AccessList()
        self.shared_secret_list = SharedSecrets()


        self.face_id_list = []

    def save_db(self):
        if self.db:
            wb = self.db.write_batch()
            wb.put(b'device_list', self.device_list.SerializeToString())
            wb.put(b'service_list', self.service_list.SerializeToString())
            wb.put(b'access_list', self.access_list.SerializeToString())
            wb.put(b'shared_secret_list',self.shared_secret_list.SerializeToString())
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
        cur_id = self.keychain.createIdentityV2(Name(self.system_prefix),EcKeyParams())
        self.system_anchor = cur_id.getDefaultKey().getDefaultCertificate()
        logging.info("Server finishes the step 1 initialization")

        # Step Two: App Layer Support (from Level DB)
        # 1. DEVICES: get all the certificates for devices from storage
        ret = self.db.get(b'device_list')
        if ret:
            self.device_list.ParseFromString(ret)
        # 2. SERVICES: get service list and corresponding providers
        ret = self.db.get(b'service_list')
        if ret:
            srv_lst = ServiceList()
            srv_lst.ParseFromString(ret)
            self.service_list = srv_lst
        # 3. ACCESS CONTROL: get all the encryption/decryption key pairs
        ret = self.db.get(b'access_list')
        if ret:
            self.access_list.ParseFromString(ret)
        # 4. SHARED SECRETS: get all shared secrets
        ret = self.db.get(b'shared_secret_list')
        if ret:
            self.shared_secret_list.ParseFromString(ret)
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
        # for now, there is only one UDP multicast face, so we don't need to care about this

    async def express_interest(self, interest):
        ret = await fetch_data_packet(self.face, interest)
        result = {}
        if isinstance(ret, Data):
            result["response_type"] = 'Data'
            result["name"] = ret.name.toUri()
            result["content_type"] = decode_content_type(ret.metaInfo.type)
            result["freshness_period"] = "{:.3f}s".format(ret.metaInfo.freshnessPeriod / 1000.0)
            if ret.metaInfo.finalBlockId:
                result["final_block_id"] = ret.metaInfo.finalBlockId.toEscapedString()
            result["signature_type"] = type(ret.signature).__name__

        elif isinstance(ret, NetworkNack):
            result["response_type"] = 'NetworkNack'
            result["reason"] = decode_nack_reason(ret.getReason())

        elif ret is None:
            result["response_type"] = 'Timeout'
        return result

    async def on_sign_on_interest(self,face: Face, _prefix: Name):

        done = threading.Event()
        result = {'DeviceIdentifier': None,
                  'DeviceCapability': None,
                  'N1PublicKey': None,
                  'N2PrivateKey':None,
                  'N2PublicKey':None,
                  'SharedKey':None,
                  'Salt':None,
                  'TrustAnchorDigest':None,
                  'SharedPublicKey':None,
                  'SharedSymmetricKey':None,
                  'CertName':None}
        registerID = -1

        TLV_GenericNameComponent = 8
        TLV_SEC_BOOT_CAPACITIES = 160
        TLV_AC_ECDH_PUB_N1 = 162
        TLV_AC_ECDH_PUB_N2 = 163
        TLV_AC_SALT = 131


        def onInterest(prefix, interest: Interest, _face: Face, interestFilterId, filter):
            try:
                nonlocal result,registerID
                logging.info("[SIGN ON]: interest received")
                logging.info(interest.name)
                ## parse the parameters of interest
                if not interest.hasParameters():
                    raise ValueError("[SIGN ON]: interest has no parameters")
                tlv_ret = TLVTree(interest.applicationParameters.toBytes()).get_dict()
                logging.info(interest.applicationParameters.toBytes())
                logging.info(tlv_ret)
                d_i = tlv_ret.get(TLV_GenericNameComponent)
                d_c = tlv_ret.get(TLV_SEC_BOOT_CAPACITIES)
                n1_pub = tlv_ret.get(TLV_AC_ECDH_PUB_N1)
                if not d_i or not d_c or not n1_pub:
                    raise KeyError("[SIGN ON]: lack interest parameters")
                result['DeviceIdentifier'] = d_i
                result['DeviceCapability'] = d_c
                result['N1PublicKey'] = n1_pub

                # get pre-shared keys from level db
                found = False
                for ss in self.shared_secret_list.sharedsecrets:
                    d_i_str = result["DeviceIdentifier"].decode('utf-8')
                    if ss.device_identifier == d_i_str:
                        result['SharedPublicKey'] = bytes.fromhex(ss.public_key)
                        result['SharedSymmetricKey'] = bytes.fromhex(ss.symmetric_key)
                        found = True
                        break
                if not found:
                    raise ValueError("[SIGN ON]: no preshared information about the device")

                # TODO: check whether the device has already bootstrapped
                # TODO: Verify the signature:pre_installed_ecc_key
                shared_public_key = Blob(result['SharedPublicKey'])

                # trust anchor
                trust_anchor_bytes = self.system_anchor.wireEncode().toBytes()
                logging.info(self.system_anchor)
                logging.info(self.system_anchor.getContent().toBytes())
                logging.info(self.system_anchor.wireEncode().toHex())
                logging.info(trust_anchor_bytes)
                #trust_anchor_bytes = bytes(self.system_anchor.__str__(),'utf-8')
                m = sha256()
                m.update(trust_anchor_bytes)
                result['TrustAnchorDigest'] = m.digest()
                # ECDH
                ecdh = ECDH()
                result['N2PrivateKey'] = ecdh.prv_key.to_string()
                result['N2PublicKey'] = ecdh.pub_key.to_string()
                # random 16 bytes for salt
                result['Salt'] = urandom(16)
                ecdh.encrypt(result['N1PublicKey'],result['Salt'])
                result['SharedKey'] = ecdh.derived_key

                # encode data content
                tlv_encoder = TlvEncoder()
                tlv_encoder.writeBlobTlv(TLV_AC_SALT,result['Salt'])
                tlv_encoder.writeBlobTlv(TLV_AC_ECDH_PUB_N2,result['N2PublicKey'])
                tlv_encoder.writeBuffer(trust_anchor_bytes)

                # data packet
                logging.info(result)
                data_content = tlv_encoder.getOutput()
                sign_on_data = Data(interest.name)
                sign_on_data.content = data_content
                sign_on_data.metaInfo.freshnessPeriod = 5000
                # sign with pre_installed_hmac_key
                shared_symmetric_key = Blob(result['SharedSymmetricKey'])
                signature = HmacWithSha256Signature()
                signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
                #signature.getKeyLocator().setKeyName(Name('key1'))
                sign_on_data.setSignature(signature)
                self.keychain.signWithHmacWithSha256(sign_on_data, shared_symmetric_key)
                # reply data
                _face.putData(sign_on_data)
                logging.info(result)
                nonlocal done
                _face.removeRegisteredPrefix(registerID)
                done.set()
            except error as e:
                logging.error(str(e))
                logging.error("[SIGN ON]: ERROR")
                _face.removeRegisteredPrefix(registerID)
                done.set()
                result = None

        def onRegisterFailed(prefix: Name):
            logging.error("register failed")

        def onRegisterSucceed(_prefix, registeredPrefixId):
            nonlocal registerID
            registerID = registeredPrefixId

        async def wait_for_event():
            ret = False
            while not ret:
                ret = done.wait(0.01)
                await asyncio.sleep(0.01)

        try:
            logging.info("REGISTER [SIGN ON] PREFIX INTEREST")
            logging.info(_prefix)
            face.registerPrefix(_prefix, onInterest, onRegisterFailed, onRegisterSucceed)
            await wait_for_event()
            return result
        except (ConnectionRefusedError, BrokenPipeError) as error:
            return error


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


    async def on_certificate_request_interest(self,face: Face, _prefix: Name, stage_one_result):
        done = threading.Event()
        registerID = -1

        TLV_GenericNameComponent = 8
        TLV_AC_ECDH_PUB_N1 = 162
        TLV_AC_ECDH_PUB_N2 = 163
        TLV_SEC_BOOT_ANCHOR_DIGEST = 161
        TLV_Data = 6
        TLV_AC_AES_IV = 135
        TLV_AC_ENCRYPTED_PAYLOAD = 136


        def onInterest(prefix, interest: Interest, _face: Face, interestFilterId, filter):
            try:
                logging.info("[CERT REQ]: interest received")
                logging.info(interest.name)
                # TODO:Verifying the signature:pre_installed_ecc_key
                ## parse the parameters of interest
                nonlocal registerID
                if not interest.hasParameters():
                    raise ValueError("[CERT REQ]: interest has no parameters")
                tlv_ret = TLVTree(interest.applicationParameters.toBytes()).get_dict()
                logging.info(interest.applicationParameters.toBytes())
                logging.info(tlv_ret)
                d_i = tlv_ret.get(TLV_GenericNameComponent)
                n2_pub = tlv_ret.get(TLV_AC_ECDH_PUB_N2)
                anchor_digest = tlv_ret.get(TLV_SEC_BOOT_ANCHOR_DIGEST)
                n1_pub = tlv_ret.get(TLV_AC_ECDH_PUB_N1)
                ## verify whether the parameters are as required
                if not d_i or not n2_pub or not anchor_digest or not n1_pub:
                    raise KeyError("[CERT REQ]: lacking interest parameters")
                nonlocal stage_one_result
                logging.info(stage_one_result)
                logging.info(d_i)
                logging.info(n2_pub)
                logging.info(anchor_digest)
                logging.info(n1_pub)
                if d_i != stage_one_result['DeviceIdentifier'] or \
                        n2_pub != stage_one_result['N2PublicKey'] or \
                        anchor_digest != stage_one_result['TrustAnchorDigest'] or \
                        n1_pub != stage_one_result['N1PublicKey']:
                    raise ValueError("[CERT REQ]: unauthenticated request")

                # anchor signed certificate
                # create identity and key for the device
                device_name = Name(self.system_prefix + '/' + d_i.decode('utf-8'))
                cert_id = self.keychain.createIdentityV2(device_name, EcKeyParams())
                cert = cert_id.getDefaultKey().getDefaultCertificate()
                cert_bytes = cert.wireEncode().toBytes()
                cert_prv_key = self.decode_crypto_private_key(self.get_crypto_private_key(cert))
                stage_one_result['CertName'] = cert.getKeyName().__str__()
                # AES
                iv = urandom(16)
                cipher = AES.new(stage_one_result['SharedKey'],AES.MODE_CBC,iv)
                ct_bytes = cipher.encrypt(cert_prv_key)
                logging.info('Symmetic Key')
                logging.info(stage_one_result['SharedKey'])
                # AES IV
                logging.info("IV:")
                logging.info(iv)
                # encrpted device private key with temporary symmetric key
                ct = b64encode(ct_bytes)
                logging.info("Cipher:")
                logging.info(ct)

                # encode data content
                tlv_encoder = TlvEncoder()
                tlv_encoder.writeBlobTlv(TLV_AC_ENCRYPTED_PAYLOAD,ct)
                tlv_encoder.writeBlobTlv(TLV_AC_AES_IV,iv)
                tlv_encoder.writeBuffer(cert_bytes)

                # data packet
                data_content = tlv_encoder.getOutput()
                cert_req_data = Data(interest.name)
                cert_req_data.content = data_content
                cert_req_data.metaInfo.freshnessPeriod = 5000
                # sign with pre_installed_hmac_key
                shared_symmetric_key = Blob(stage_one_result['SharedSymmetricKey'])
                signature = HmacWithSha256Signature()
                signature.getKeyLocator().setType(KeyLocatorType.KEYNAME)
                # signature.getKeyLocator().setKeyName(Name('key1'))
                cert_req_data.setSignature(signature)
                self.keychain.signWithHmacWithSha256(cert_req_data, shared_symmetric_key)
                # reply data
                _face.putData(cert_req_data)
                nonlocal done
                _face.removeRegisteredPrefix(registerID)
                done.set()
            except error as e:
                logging.error(str(e))
                logging.error("[CERT REQ]: ERROR")
                _face.removeRegisteredPrefix(registerID)
                done.set()
                stage_one_result = None

        def onRegisterFailed(prefix: Name):
            logging.error("register failed")

        def onRegisterSucceed(_prefix, registeredPrefixId):
            nonlocal registerID
            registerID = registeredPrefixId

        async def wait_for_event():
            ret = False
            while not ret:
                ret = done.wait(0.01)
                await asyncio.sleep(0.01)

        try:
            logging.info("REGISTER [CERT REQ] PREFIX INTEREST")
            logging.info(_prefix)
            face.registerPrefix(_prefix, onInterest, onRegisterFailed, onRegisterSucceed)
            await wait_for_event()
            return stage_one_result
        except (ConnectionRefusedError, BrokenPipeError) as error:
            return error


    async def bootstrapping(self):
        #sign on
        ret = await self.on_sign_on_interest(self.face,Name('/ndn/sign-on'))
        if not ret:
            return {'st_code': 500}
        #certificate request
        ret = await self.on_certificate_request_interest(self.face,Name(self.system_prefix + '/cert'),ret)
        if not ret:
            return {'st_code': 500}
        new_device = self.device_list.device.add()
        new_device.device_id = ret["DeviceIdentifier"]
        new_device.device_info = ret["DeviceCapability"]
        new_device.device_cert_name = ret["CertName"]
        return {'st_code':200,'device_id': ret['DeviceIdentifier'].decode('utf-8')}


    def get_access_status(self, parameter_list):
        pass

    def invoke_service(self, parameter_list):
        pass

    async def add_face(self, uri):
        interest = self.make_localhost_command('faces', 'create', uri=uri)
        ret = await fetch_data_packet(self.face, interest)
        if isinstance(ret, Data):
            response = CreateFaceResponse()
            try:
                ProtobufTlv.decode(response, ret.content)
                logging.fatal('Successfully created a NFD face {:d}'.format(response.face_id))
                return response.face_id
            except RuntimeError as exc:
                logging.fatal('Add Face Response Decoding failed %s', exc)
        else:
            logging.fatal('Local NFD no response')
        return None

    async def query_face_id(self, uri):
        query_filter = FaceQueryFilterMessage()
        query_filter.face_query_filter.uri = uri.encode()
        query_filter_msg = ProtobufTlv.encode(query_filter)
        name = Name("/localhost/nfd/faces/query").append(Name.Component(query_filter_msg))
        interest = Interest(name)
        interest.mustBeFresh = True
        interest.canBePrefix = True
        logging.info("Send Interest packet {:s}".format(name.toUri()))
        ret = await fetch_data_packet(self.face, interest)
        if not isinstance(ret, Data):
            return None
        msg = FaceStatusMessage()
        try:
            ProtobufTlv.decode(msg, ret.content)
        except RuntimeError as exc:
            logging.fatal("Decoding Error %s", exc)
            return None
        if len(msg.face_status) <= 0:
            return None
        return msg.face_status[0].face_id

    ## copied from NDN-CC
    async def remove_face(self, face_id: int):
        interest = self.make_localhost_command('faces', 'destroy', face_id=face_id)
        return await self.issue_command_interest(interest)

    ## copied from NDN-CC
    async def add_route(self, name: str, face_id: int):
        interest = self.make_localhost_command('rib', 'register',
                                               name=Name(name), face_id=face_id)
        ret = await fetch_data_packet(self.face, interest)
        if isinstance(ret, Data):
            response = ControlResponseMessage()
            try:
                ProtobufTlv.decode(response, ret.content)
                logging.info("Issue command Interest with result: {:d}".format(response.control_response.st_code))
                if response.control_response.st_code <= 399:
                    return True
            except RuntimeError as exc:
                logging.fatal('Decode failed %s', exc)
        return False

    ## copied from NDN-CC
    async def remove_route(self, name: str, face_id: int):
        interest = self.make_localhost_command('rib', 'unregister',
                                     name=Name(name), face_id=face_id)
        ret = await self.issue_command_interest(interest)

    ## copied from NDN-CC
    async def set_strategy(self, name: str, strategy: str):
        interest = self.make_localhost_command('strategy-choice', 'set',
                                               name=Name(name), strategy=Name(strategy))
        ret = await fetch_data_packet(self.face, interest)
        if isinstance(ret, Data):
            response = ControlResponseMessage()
            try:
                ProtobufTlv.decode(response, ret.content)
                logging.info("Issue command Interest with result: {:d}".format(response.control_response.st_code))
                if response.control_response.st_code <= 399:
                    return True
            except RuntimeError as exc:
                logging.fatal('Decode failed %s', exc)
        return False

    ## copied from NDN-CC
    async def unset_strategy(self, name: str):
        interest = self.make_localhost_command('strategy-choice', 'unset', name=Name(name))
        return await self.issue_command_interest(interest)

    ## copied from NDN-CC
    async def issue_command_interest(self, interest):
        ret = await fetch_data_packet(self.face, interest)
        if isinstance(ret, Data):
            response = ControlResponseMessage()
            try:
                ProtobufTlv.decode(response, ret.content)
                logging.info("Issue command Interest with result: {:d}".format(response.control_response.st_code))
            except RuntimeError as exc:
                logging.fatal('Decode failed %s', exc)
        return None

    ## copied from NDN-CC
    def make_localhost_command(self, module, verb, **kwargs):
        name = Name('/localhost/nfd').append(module).append(verb)

        # Command Parameters
        cmd_param = ControlCommandMessage()
        if 'name' in kwargs:
            name_param = kwargs['name']
            for compo in name_param:
                cmd_param.control_parameters.name.component.append(compo.getValue().toBytes())
        if 'strategy' in kwargs:
            name_param = kwargs['strategy']
            for compo in name_param:
                cmd_param.control_parameters.strategy.name.component.append(compo.getValue().toBytes())
        for key in ['uri', 'local_uri']:
            if key in kwargs:
                setattr(cmd_param.control_parameters, key, kwargs[key].encode('utf-8'))
        for key in ['face_id', 'origin', 'cost', 'capacity', 'count', 'base_cong_mark', 'def_cong_thres',
                    'mtu', 'flags', 'mask', 'exp_period']:
            if key in kwargs:
                setattr(cmd_param.control_parameters, key, kwargs[key])
        param_blob = ProtobufTlv.encode(cmd_param)
        name.append(Name.Component(param_blob))

        # Command Interest Components
        ret = Interest(name)
        ret.canBePrefix = True
        self.face.makeCommandInterest(ret)
        return ret

    async def run(self):
        # create face and set up face's keychain and default cert
        self.face = Face()
        self.face.setCommandSigningInfo(self.keychain, self.system_anchor.name)
        interest = Interest("/localhost/nfd/faces/events")
        interest.mustBeFresh = True
        interest.canBePrefix = True
        interest.interestLifetimeMilliseconds = 1000
        try:
            def empty(*_args, **_kwargs):
                pass
            self.face.expressInterest(interest, empty, empty, empty)
            logging.info("Face creation succeeded")
        except (ConnectionRefusedError, BrokenPipeError, OSError):
            logging.fatal("Face creation failed")

        self.setup_sd()

        while self.running and self.face is not None:
            try:
                self.face.processEvents()
            except AttributeError:
                logging.info("Process Events Error.")
            await asyncio.sleep(0.01)

    @staticmethod
    def start_controller(emit_func):
        done = threading.Event()
        controller = None

        def create_and_run():
            nonlocal controller, done
            controller = Controller(emit_func)
            controller.system_init()
            work_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(work_loop)
            done.set()
            try:
                work_loop.run_until_complete(controller.run())
            finally:
                work_loop.close()

        thread = threading.Thread(target=create_and_run)
        thread.setDaemon(True)
        thread.start()
        done.wait()
        return controller

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
