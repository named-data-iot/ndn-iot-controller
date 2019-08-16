import pyqrcode
import json

#ECDSA key is generated at: https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

info = {}
info["device_identifier"] = "device-49120"

info["public_key"] = "E0EBFE7BB2B646E81ADE4E81D7C8DC896EB5F4B45E0214B2595B78825A6044A0CE17CA3D3D8B71A825E6486C935BDD42CF6190E015DD297C411CC3FF04104676"
#private key: 0x47741034c4908cd9c1c03a8bbaf796c981a240ad37e20765f7863cbac5462ef1
info["symmetric_key"] = "62F0D2EAC68C0D7B07F0B79711B093BB"

shared_info = pyqrcode.create(json.dumps(info))
shared_info.png('shared_info.png', scale=5)
cmd_line_qr = shared_info.terminal(quiet_zone=1)
print(cmd_line_qr)




