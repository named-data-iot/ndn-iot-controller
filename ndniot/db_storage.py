from ndn.encoding import TlvModel, BytesField, RepeatedField, ModelField, UintField, NameField


class DeviceItem(TlvModel):
    device_id = BytesField(1)
    device_info = BytesField(2)
    aes_key = BytesField(3)
    device_identity_name = NameField()


class DeviceList(TlvModel):
    devices = RepeatedField(ModelField(1, DeviceItem))


class ServiceItem(TlvModel):
    service_id = UintField(1)
    exp_time = UintField(2)
    service_name = NameField()


class ServiceList(TlvModel):
    services = RepeatedField(ModelField(1, ServiceItem))


class AccessType:
    NO_LIMITATION = 0
    CONTROLLER_ONLY = 1
    UNDER_SAME_PREFIX = 2


class AccessItem(TlvModel):
    prefix = NameField()
    type = UintField(2)
    encryption_key = BytesField(3)
    decryption_key = BytesField(4)


class AccessList(TlvModel):
    access_items = RepeatedField(ModelField(1, AccessItem))


class SharedSecretsItem(TlvModel):
    device_identifier = BytesField(1)
    public_key = BytesField(2)
    symmetric_key = BytesField(3)


class SharedSecrets(TlvModel):
    shared_secrets = RepeatedField(ModelField(1, SharedSecretsItem))
