from ndn.encoding import TlvModel, BytesField, RepeatedField, ModelField, UintField


class DeviceItem(TlvModel):
    device_id = BytesField(1)
    device_info = BytesField(2)
    device_cert_name = BytesField(3)


class DeviceList(TlvModel):
    device = RepeatedField(ModelField(1, DeviceItem))


class ServiceItem(TlvModel):
    service_id = UintField(1)
    service_name = BytesField(2)
    exp_time = UintField(3)


class ServiceList(TlvModel):
    service = RepeatedField(ModelField(1, ServiceItem))


class AccessType:
    NO_LIMITATION = 0
    CONTROLLER_ONLY = 1
    UNDER_SAME_PREFIX = 2


class AccessItem(TlvModel):
    prefix = BytesField(1)
    type = UintField(2)
    encryption_key = BytesField(3)
    decryption_key = BytesField(4)


class AccessList(TlvModel):
    access = RepeatedField(ModelField(1, AccessItem))


class SharedSecretsItem(TlvModel):
    device_identifier = BytesField(1)
    public_key = BytesField(2)
    symmetric_key = BytesField(3)


class SharedSecrets(TlvModel):
    shared_secrets = RepeatedField(ModelField(1, SharedSecretsItem))
