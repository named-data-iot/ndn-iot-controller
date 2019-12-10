import subprocess
import base64
from Cryptodome.IO.PKCS8 import unwrap
from ndn.encoding import parse_and_check_tl
from ndn.app_support.security_v2 import SafeBag, SecurityV2TypeNumber

def get_prv_key_from_safe_bag(id_name):
    p = subprocess.run(['ndnsec-export', id_name, '-P', '1234'], stdout=subprocess.PIPE)
    wire = base64.b64decode(p.stdout)
    wire = parse_and_check_tl(wire, SecurityV2TypeNumber.SAFE_BAG)
    bag = SafeBag.parse(wire)
    algo, key, param = unwrap(bytes(bag.encrypted_key_bag), '1234')
    return key

if __name__ == '__main__':
    get_prv_key_from_safe_bag('/example')