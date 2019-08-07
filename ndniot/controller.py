import asyncio
import logging
import threading
import plyvel
import struct
import time
from pyndn import Face, Interest, Data, Name, NetworkNack, InterestFilter
from pyndn.security import KeyChain, Pib
from pyndn.encoding import ProtobufTlv
import pyndn.transport
from pyndn.transport.unix_transport import UnixTransport
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.certificate_v2 import CertificateV2
from .asyncndn import fetch_data_packet, on_sign_on_interest,on_certificate_request_interest,\
    decode_dict, decode_list, decode_name, decode_content_type, decode_nack_reason, connection_test
from .nfd_face_mgmt_pb2 import ControlCommandMessage, ControlResponseMessage, CreateFaceResponse, \
    FaceQueryFilterMessage, FaceStatusMessage
from .db_storage_pb2 import DeviceList, ServiceList, AccessList,SharedSecrets

default_prefix = "/ndn-iot"
default_udp_multi_uri = "udp4://224.0.23.170:56363"
controller_port = 6363

class Controller:
    def __init__(self, emit_func):
        self.running = True
        self.networking_ready = False
        self.emit = emit_func
        self.keychain = KeyChain()
        self.face = None

        self.system_prefix = None
        self.system_anchor = None
        self.db = None
        self.device_list = DeviceList()
        self.service_list = ServiceList()
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
        cur_id = self.keychain.createIdentityV2(Name(self.system_prefix))
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
            self.service_list.ParseFromString(ret)
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
        # 2. Set up NFD's route from IoT system prefix to multicast faces
        face_id = await self.query_face_id(default_udp_multi_uri)
        logging.info("Found UDP multicast face {:d}".format(face_id))
        if face_id:
            ret = await self.add_route(self.system_prefix, face_id)
            if ret is True:
                self.networking_ready = True
                logging.info("Server finishes the step 3 initialization")
            else:
                logging.fatal("Cannot set up the route for IoT prefix")
        else:
            logging.fatal("Cannot find existing udp multicast face")
        # 3. Set up NFD's multicast strategy for IoT system namespace
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

    async def bootstrapping(self):
        ### [SIGN ON - response]: return trust anchor and N2
        ret = await on_sign_on_interest(self.face,Name('/ndn/sign-on'))

        ### [CERTIFICATE REQUEST - response]: return certificate
        ret = await on_certificate_request_interest(self.face,Name(controller.system_prefix + '/cert'))

        result = {}
        return result

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
        return await self.issue_command_interest(interest)

    ## copied from NDN-CC
    async def set_strategy(self, name: str, strategy: str):
        interest = self.make_localhost_command('strategy-choice', 'set',
                                     name=Name(name), strategy=Name(strategy))
        return await self.issue_command_interest(interest)

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
                logging.info("Issue command Interest with result: {:d}".format(response.st_code))
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
