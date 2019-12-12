import asyncio
import time
import os
import logging
from ndniot.controller import Controller
from ndniot.db_storage import *
from PIL import Image
from pyzbar.pyzbar import decode
import json
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2

def app_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG,
                        style='{')

    base_path = os.getcwd()
    # Serve static content from /static
    app = web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader(os.path.join(base_path, 'templates')))
    app.router.add_static(prefix='/static', path=os.path.join(base_path, 'static'))
    routes = web.RouteTableDef()
    # Create SocketIO async server for controller
    sio = socketio.AsyncServer(async_mode='aiohttp')
    sio.attach(app)
    controller = Controller(sio.emit)
    controller.system_init()

    def render_template(template_name, request, **kwargs):
        return aiohttp_jinja2.render_template(template_name, request, context=kwargs)

    def redirect(route_name, request, **kwargs):
        raise web.HTTPFound(request.app.router[route_name].url_for().with_query(kwargs))

    def process_list(lst):
        for it in lst:
            for k, v in it.items():
                if isinstance(v, bytes):
                    it[k] = v.decode()

    @routes.get('/')
    @aiohttp_jinja2.template('index.html')
    async def index(request):
        return

    @routes.get('/system-overview')
    @aiohttp_jinja2.template('system-overview.html')
    async def system_overview(request):
        metainfo = []
        metainfo.append({"information":"System Prefix", "value": controller.system_prefix})
        # metainfo.append({"information":"System Anchor", "value": controller.system_anchor})
        metainfo.append({"information": "Available Devices", "value": str(len(controller.device_list.devices))})
        metainfo.append({"information": "Available Services", "value": str(len(controller.service_list.services))})
        return {'metainfo': metainfo}

    ### bootstrapping
    @routes.get('/bootstrapping')
    @aiohttp_jinja2.template('bootstrapping.html')
    async def bootstrapping(request):
        secrets = list()
        for secret in controller.shared_secret_list.shared_secrets:
            secrets.append({'deviceIdentifier': str(bytes(secret.device_identifier).decode()),
                            'publicKey': str(bytes(secret.public_key).decode()),
                            'symmetricKey': str(bytes(secret.symmetric_key).decode())})

        logging.info("bootstapping")
        logging.info(secrets)
        return {'existing_shared_secrets': secrets}

    ### trigger bootstrapping process
    @routes.post('/exec/bootstrapping')
    async def bootstrap_device(request):
        ret = await controller.bootstrapping()
        logging.info("Bootstrap result:")
        logging.info(ret)
        return web.json_response(ret)

    ### room
    @routes.get('/room')
    async def room(request):
        room_list = []
        return render_template("room.html", request, room_list= room_list)

    ###add shared_secrets
    @routes.post('/add/shared_secrets')
    async def add_shared_secrets(request):
        data = await request.post()
        logging.info(data)
        up_img = data['file'].file
        decoded = decode(Image.open(up_img))
        logging.info(decoded)
        shared_info = json.loads(decode(Image.open(up_img))[0].data)
        if not shared_info["device_identifier"] or not shared_info["public_key"] or not shared_info["symmetric_key"]:
            return web.json_response({"st_code": 500})
        for secret in controller.shared_secret_list.shared_secrets:
            if bytes(secret.device_identifier).decode() == shared_info["public_key"]:
                return web.json_response({"st_code": 500})
        new_shared_secret = SharedSecretsItem()
        new_shared_secret.device_identifier = shared_info["device_identifier"].encode()
        new_shared_secret.public_key = shared_info["public_key"].encode()
        new_shared_secret.symmetric_key = shared_info["symmetric_key"].encode()
        controller.shared_secret_list.shared_secrets.append(new_shared_secret)

        secrets = list()
        for secret in controller.shared_secret_list.shared_secrets:
            secrets.append({'deviceIdentifier': str(bytes(secret.device_identifier).decode()),
                            'publicKey': str(bytes(secret.public_key).decode()),
                            'symmetricKey': str(bytes(secret.symmetric_key).decode())})
        res = dict()
        res['sharedsecrets'] = secrets
        res['st_code'] = 200
        return web.json_response(res)

    ###delete shared_secrets
    @routes.post('/delete/shared_secrets')
    async def delete_shared_secrets(request):
        data = await request.json()
        controller.shared_secret_list.shared_secrets = [ss for ss in controller.shared_secret_list.shared_secrets
                                                        if bytes(ss.public_key).decode() != data['publicKey']]
        return web.json_response({"st_code": 200})


    ### device list
    @routes.get('/device-list')
    @aiohttp_jinja2.template('device-list.html')
    async def device_list(request):
        ret =[]
        for device in controller.device_list.devices:
            ret.append({'deviceId': bytes(device.device_id).decode(),
                        'deviceInfo': bytes(device.device_info).decode(),
                        'deviceIdentityName': bytes(device.device_identity_name).decode()})
        return {'device_list': ret}

    @routes.post('/delete/device')
    async def remove_device(request):
        data = await request.json()
        # delete from keychain
        controller.app.keychain.del_identity(data['deviceIdentityName'])
        # delete from database
        controller.device_list.devices = [device for device in controller.device_list.devices
                                          if bytes(device.device_identity_name).decode() != data['deviceIdentityName']]
        # TODO: delete service information of this device
        return web.json_response({"st_code": 200})

    ### service list
    @routes.get('/service-list')
    @aiohttp_jinja2.template('service-list.html')
    async def service_list(request):
        list = []
        for service in controller.service_list.services:
            list.append({'serviceId': str(service.service_id), 'serviceName': str(service.service_name),
                         'expTime': str(service.exp_time)})
        return {'service_list': list}

    ### service invocation
    @routes.get('/invoke-service', name='invoke-service')
    @aiohttp_jinja2.template('invoke-service.html')
    async def invoke_service(request):
        return

    @routes.post('/exec/invoke-service')
    async def trigger_invocation(request):
        return redirect('invoke-service', request)

    ### access control
    @routes.get('/access-control', name='access-control')
    @aiohttp_jinja2.template('access-control.html')
    async def access_control(request):
        load = []
        if not load:
            service_prefix_list = []
        else:
            service_prefix_list = load["access"]
        # The following code is only for sample use
        return {'service_prefix_list': service_prefix_list}

    @routes.post('/exec/update-access-rights')
    async def update_access_rights(request):
        r_json = await request.json()
        print(r_json['prefix'])
        print(r_json['access_type'])
        return redirect('access-control', request)

    @routes.get('/ndn-ping')
    @aiohttp_jinja2.template('ndn-ping.html')
    async def ndn_ping(request):
        return

    @routes.post('/exec/ndn-ping')
    async def exec_ndn_ping(request):
        controller.decode_crypto_public_key(controller.get_crypto_public_key(controller.system_anchor))
        r_json = await request.json()
        name = r_json['name']
        can_be_prefix = r_json['can_be_prefix']
        must_be_fresh = r_json['must_be_fresh']
        signed_interest = r_json['signed_interest']
        param = r_json['application_parameter']
        try:
            interest_lifetime = float(r_json['interest_lifetime']) * 1000.0
        except ValueError:
            interest_lifetime = 4000.0

        interest = Interest(name)
        interest.canBePrefix = can_be_prefix
        interest.mustBeFresh = must_be_fresh
        interest.interestLifetimeMilliseconds = interest_lifetime
        if param != '':
            try:
                interest.applicationParameters = int(param).to_bytes(1, 'little')
            except ValueError:
                pass
        interest.appendParametersDigestToName()
        if signed_interest:
            data_parameter = Data(interest.name)
            controller.keychain.sign(data_parameter, controller.system_anchor.getName())
            data_parameter_blob_bytes = data_parameter.wireEncode().toBytes()
            existing_parameter_bytes = interest.getApplicationParameters().toBytes()
            whole_parameter_bytes = existing_parameter_bytes + data_parameter_blob_bytes
            interest.setApplicationParameters(Blob(whole_parameter_bytes))
        st_time = time.time()
        ret = await controller.express_interest(interest)
        ed_time = time.time()
        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    app.add_routes(routes)
    asyncio.ensure_future(controller.run())
    try:
        web.run_app(app, port=6060)
    finally:
        controller.save_db()

if __name__ == '__main__':
    app_main()
