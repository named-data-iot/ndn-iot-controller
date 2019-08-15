import pyqrcode
import json

#ECDSA key is generated at: https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

info = {}
info["device_identifier"] = "LED0"
info["public_key"] = "04bec009beffd5e1427e98282176bf35bb9d12f08416877762a24fa229589a97f89274747042a5d531a27e33cfcac8ec2ee2910985203cec622189b34cd17c1021"
#private key: 0x47741034c4908cd9c1c03a8bbaf796c981a240ad37e20765f7863cbac5462ef1
info["symmetric_key"] = "5469B8C0B62877701CDDE8899203FDDE"

shared_info = pyqrcode.create(json.dumps(info))
shared_info.png('shared_info.png', scale=5)
cmd_line_qr = shared_info.terminal(quiet_zone=1)
print(cmd_line_qr)




