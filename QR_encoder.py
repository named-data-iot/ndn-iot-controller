import pyqrcode
import json

#ECDSA key is generated at: https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

info = {}
info["device_identifier"] = "LED0"

info["public_key"] = b"\x90\xa6\xbc\xe8\x00W\xc0e\xe9\x8a\\\x05(d\x9a\x99y\xc1\x10\x0f\xf8\x8a\xd0IU\xaa\xbf\xbb\x1b\\\xe2\xab9W\x89\x96\xb5\xee:\xf9_\xd3\x89\x15\xdc3\x7fg\xcaRb\t\xbe\x88Y\xe2\xbc\xcf\xbd\xd4\x18\xdd8\x01".hex()
#private key: 0x47741034c4908cd9c1c03a8bbaf796c981a240ad37e20765f7863cbac5462ef1
info["symmetric_key"] = "5469B8C0B62877701CDDE8899203FDDE"

shared_info = pyqrcode.create(json.dumps(info))
shared_info.png('shared_info.png', scale=5)
cmd_line_qr = shared_info.terminal(quiet_zone=1)
print(cmd_line_qr)




