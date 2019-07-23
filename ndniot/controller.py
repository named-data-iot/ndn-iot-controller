import asyncio
import logging
import threading
from pyndn import Face, Interest, Data, Name, NetworkNack
from pyndn.security import KeyChain, Pib
from pyndn.encoding import ProtobufTlv
from pyndn.transport.unix_transport import UnixTransport
from pyndn.security.pib.pib_key import PibKey
from pyndn.security.v2.certificate_v2 import CertificateV2
from .asyncndn import fetch_data_packet, decode_dict, decode_list, decode_name, decode_content_type, decode_nack_reason, connection_test
import plyvel

default_prefix = b"/ndn-iot"

def run_until_complete(event):
    asyncio.set_event_loop(asyncio.new_event_loop())
    return asyncio.get_event_loop().run_until_complete(event)

class Controller:
    def __init__(self, emit_func):
        self.running = True
        self.emit = emit_func
        self.keychain = KeyChain()
        self.face = None
        self.system_prefix = None
        self.system_anchor = None
        self.db = None

    def system_init(self):
        # create or get existing state
        # Step One: Meta Info
        # 1. get system prefix from storage (from Level DB)
        # 2. get system root anchor certificate and private key (from keychain)
        self.db = plyvel.DB('./storage/',create_if_missing=True)
        self.system_prefix = Name(self.db.get(b'system_prefix', default_prefix).decode("utf-8"))
        cur_id = self.keychain.createIdentityV2(self.system_prefix)
        self.system_anchor = cur_id.getDefaultKey().getDefaultCertificate()

        # Step Two: App Layer Support (from Level DB)
        # 1. DEVICES: get all the certificates for devices from storage
        # 2. SERVICES: get service list and corresponding providers
        # 3. ACCESS CONTROL: get all the encryption/decryption key pairs

        # Step Three: Networking
        # 1. Create NFD's UDP Multicast Face, BLE Multicast Face, etc.
        # 2. Set up NFD's route from IoT system prefix to multicast faces
        # 3. Set up NFD's multicast strategy for IoT system namespace


    def blocking_express_interest(self, interest):
        ret = run_until_complete(fetch_data_packet(self.face, interest))
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

    def bootstrapping(self, parameter_list):
        pass

    def get_access_status(self, parameter_list):
        pass

    def invoke_service(self, parameter_list):
        pass

    async def run(self):
        while self.running:
            logging.info("Restarting face...")
            self.face = Face()
            self.face.setCommandSigningInfo(self.keychain, self.system_anchor)
            if connection_test(self.face):
                logging.info("Face creation succeeded")
                while self.running and self.face is not None:
                    try:
                        self.face.processEvents()
                    except AttributeError:
                        logging.info("Attribute error.")
                        self.face.shutdown()
                        self.face = None
                    await asyncio.sleep(0.01)
            else:
                logging.info("Face creation failed")
            await asyncio.sleep(3)

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

if __name__ == "__main__":
    emit = "emit"
    controller = Controller.start_controller(emit)