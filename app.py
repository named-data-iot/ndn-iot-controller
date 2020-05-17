import asyncio
import time
import os
import logging
from ndniot.controller import Controller
from ndniot.db_storage import *
from ndn.encoding import Name
from PIL import Image
from pyzbar.pyzbar import decode
import json
from aiohttp import web
import socketio
import aiohttp_jinja2
import jinja2
from datetime import datetime

int_to_service_mapping = {

}

def app_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}', datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG, style='{')

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

    @routes.get('/bootstrapping')
    @aiohttp_jinja2.template('bootstrapping.html')
    async def bootstrapping(request):
        """
        bootstrapping
        :param request: request from the HTTP request
        :return: a HTTP JSON response
        """
        secrets = list()
        for secret in controller.shared_secret_list.shared_secrets:
            secrets.append({'deviceIdentifier': str(bytes(secret.device_identifier).decode()),
                            'publicKey': str(bytes(secret.public_key).decode()),
                            'symmetricKey': str(bytes(secret.symmetric_key).decode())})

        logging.info("bootstapping")
        logging.info(secrets)
        return {'existing_shared_secrets': secrets}

    # trigger bootstrapping process
    @routes.post('/exec/bootstrapping')
    async def bootstrap_device(request):
        ret = await controller.bootstrapping()
        logging.info("Bootstrap result:")
        logging.info(ret)
        return web.json_response(ret)

    # room
    @routes.get('/room')
    async def room(request):
        room_list = []
        return render_template("room.html", request, room_list= room_list)

    # add shared_secrets
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

    # delete shared_secrets
    @routes.post('/delete/shared_secrets')
    async def delete_shared_secrets(request):
        data = await request.json()
        controller.shared_secret_list.shared_secrets = [ss for ss in controller.shared_secret_list.shared_secrets
                                                        if bytes(ss.public_key).decode() != data['publicKey']]
        return web.json_response({"st_code": 200})


    # device list
    @routes.get('/device-list')
    @aiohttp_jinja2.template('device-list.html')
    async def device_list(request):
        ret = []
        for device in controller.device_list.devices:
            ret.append({'deviceId': bytes(device.device_id).decode(),
                        'deviceInfo': bytes(device.device_info).decode(),
                        'deviceIdentityName': Name.to_str(device.device_identity_name)})
        return {'device_list': ret}

    @routes.post('/delete/device')
    async def remove_device(request):
        data = await request.json()
        # delete from keychain
        try:
            # TODO bring this line back when the identity delete bug is fixed
            # controller.app.keychain.del_identity(data['deviceIdentityName'])
            os.system('ndnsec-delete ' + data['deviceIdentityName'])
        except KeyError:
            pass  # great, the key has already been removed
        # delete from database
        controller.device_list.devices = [device for device in controller.device_list.devices
                                          if Name.to_str(device.device_identity_name) != data['deviceIdentityName']]
        # delete service info
        temp_name = Name.from_str(data['deviceIdentityName'])
        controller.service_list.services = [service for service in controller.service_list.services
                                            if Name.normalize(service.service_name)[2:4] != temp_name[2:4]]
        return web.json_response({"st_code": 200})

    # service list
    @routes.get('/service-list')
    @aiohttp_jinja2.template('service-list.html')
    async def service_list(request):
        list = []
        logging.debug('/service-list response')
        for service in controller.service_list.services:
            tp = service.exp_time / 1000

            list.append({'serviceId': str(service.service_id), 'serviceName': Name.to_str(service.service_name),
                         'expTime': datetime.utcfromtimestamp(tp).strftime('%Y-%m-%d %H:%M:%S')})
        return {'service_list': list}

    # service invocation
    @routes.get('/invoke-service', name='invoke-service')
    @aiohttp_jinja2.template('invoke-service.html')
    async def invoke_service(request):
        list = []
        logging.debug('/invoke-service response')
        for service in controller.service_list.services:
            list.append({'value': Name.to_str(service.service_name), 'label': Name.to_str(service.service_name)})
        return {'service_list': list}

    @routes.post('/exec/invoke-service')
    async def exec_invoke_service(request):
        r_json = await request.json()
        name = r_json['service_name']
        is_cmd = r_json['is_cmd']
        data_or_cmd = r_json['data_or_cmd']
        param = r_json['param']

        st_time = time.time()
        ret = await controller.use_service(name, is_cmd, data_or_cmd, param)
        ed_time = time.time()

        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    # access control
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
        pass

    @routes.get('/send-interest')
    @aiohttp_jinja2.template('send-interest.html')
    async def send_interest(request):
        return

    @routes.post('/exec/send-interest')
    async def exec_send_interest(request):
        r_json = await request.json()
        name = r_json['name']
        can_be_prefix = r_json['can_be_prefix']
        must_be_fresh = r_json['must_be_fresh']
        signed_interest = r_json['signed_interest']
        param = r_json['application_parameter']

        st_time = time.time()
        ret = await controller.express_interest(name, param.encode(), must_be_fresh, can_be_prefix, signed_interest)
        ed_time = time.time()

        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return web.json_response(ret)

    @routes.get('/manage-policy', name='manage-policy')
    @aiohttp_jinja2.template('manage-policy.html')
    async def manage_policy(request):
        ret = []
        logging.debug('/invoke-service response')
        for device in controller.device_list.devices:
            ret.append({'value': Name.to_str(device.device_identity_name), 'label': Name.to_str(device.device_identity_name)})
        return {'device_list': ret}

    @routes.post('/exec/manage-policy')
    async def exec_manage_policy(request):
        r_json = await request.json()
        device_name = r_json['device_name']
        add_policy = r_json['add_policy']
        data_name = r_json['data_name']
        key_name = r_json['key_name']
        policy_name = r_json['policy_name']

        st_time = time.time()
        if add_policy:
            ret = await controller.manage_policy_add(device_name, data_name, key_name, policy_name)
        else:
            ret = await controller.manage_policy_remove(device_name, policy_name)
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
