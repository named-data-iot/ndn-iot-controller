import asyncio
import time
import os
import logging
from ndniot.controller import Controller
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
    loop = asyncio.get_event_loop()
    loop.run_until_complete(controller.iot_connectivity_init())

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
    async def index(request):
        return render_template('index.html', request)

    @routes.get('/system-overview')
    async def system_overview(request):
        metainfo = []
        metainfo.append({"information":"System Prefix","value": controller.system_prefix})
        metainfo.append({"information":"System Anchor","value": controller.system_anchor})
        if len(controller.device_list.device) > 0:
            metainfo.append({"information": "Available Devices", "value": str(len(controller.device_list.device))})
        if len(controller.service_list.service) > 0:
            metainfo.append({"information": "Available Services", "value": str(len(controller.service_list.service))})
        return render_template('system-overview.html', request, metainfo=metainfo)

    ### bootstrapping
    @routes.get('/bootstrapping')
    async def bootstrapping(request):
        load = controller.shared_secret_list.asdict()
        existing_shared_secrets = load["shared_secrets"] if load else []
        process_list(existing_shared_secrets)

        logging.info("bootstapping")
        logging.info(existing_shared_secrets)
        return render_template('bootstrapping.html', request, existing_shared_secrets=existing_shared_secrets)

    ### room
    @routes.get('/room')
    async def room(request):
        room_list = []
        return render_template("room.html", request, room_list= room_list)

    ### trigger bootstrapping process
    @routes.post('/exec/bootstrapping')
    async def bootstrap_device(request):
        ret = await controller.bootstrapping()
        logging.info("Bootstrap result:")
        logging.info(ret)
        return web.json_response(ret)

    ###add shared_secrets
    @routes.post('/add/shared_secrets')
    async def add_shared_secrets(request):
        data = await request.post()
        up_img = data['file']
        shared_info = json.loads(decode(Image.open(up_img))[0].data)
        new_shared_secret = controller.shared_secret_list.shared_secrets.add()
        try:
            new_shared_secret.device_identifier = shared_info["device_identifier"]
            new_shared_secret.public_key = shared_info["public_key"]
            new_shared_secret.symmetric_key = shared_info["symmetric_key"]
            res = controller.shared_secret_list.asdict()
            process_list(res['shared_secrets'])
            res["st_code"] = 200
            return web.json_response(res)
        except:
            return web.json_response({"st_code": 500})

    ###delete shared_secrets
    @routes.post('/delete/shared_secrets')
    async def delete_shared_secrets(request):
        r_json = await request.json()
        try:
            count = 0
            for ss in controller.shared_secret_list.shared_secrets:
                if ss.device_identifier == r_json["deviceIdentifier"] and \
                        ss.public_key == r_json["publicKey"] and \
                        ss.symmetric_key == r_json["symmetricKey"]:
                    del controller.shared_secret_list.shared_secrets[count]
                count += 1
                return web.json_response({"st_code": 200})
        except:
          return web.json_response({"st_code": 500})


    ### device list
    @routes.get('/device-list')
    async def device_list(request):
        load = json.loads(json_format.MessageToJson(controller.device_list))
        if not load:
            device_list = []
        else:
            device_list = load["device"]
        # The following code is only for sample use
        return render_template('device-list.html', request, device_list=device_list)

    @routes.post('/delete/device')
    async def remove_device(request):
        r_json = await request.json()
        device_cert_name = None
        # delete device information from level db
        try:
            count = 0
            for ss in controller.device_list.device:
                if ss.device_id == r_json["device_id"]:
                    device_id_name = ss.device_cert_name # Key name of the certificate
                    del controller.device_list.device[count]
                count += 1
        except:
            logging.error('Cannot find the deleting device in the leveldb')
            return web.json_response({"st_code": 500})
        # delete device identity in pib
        try:
            controller.keychain.deleteIdentity(Name(device_id_name))
        except:
            logging.error('Cannot find the pib-identity of the deleting device')
            return web.json_response({"st_code": 500})
        # delete service information from leveldb
        # service Name: system_prefix/%01/<service-id>/ [Device Identifier]
        # Device Identifier should not start with '/'
        for service_name in list(controller.real_service_list.keys()):
            d_id = Name(service_name)[3:].__str__()[1:] #get rid of the beginning '/'; device id shall not start with '/'
            if d_id == r_json["device_id"]:
                del controller.real_service_list[service_name]
        return web.json_response({"st_code": 200})



    ### service list
    @routes.get('/service-list')
    async def service_list(request):
        load = json.loads(json_format.MessageToJson(controller.service_list))
        if not load:
            service_list = []
        else:
            service_list = load["service"]

        for item in service_list:
            if 'expTime' in item:
                print(item)
                item['expTime'] = time.ctime(int(item['expTime']) / 1000.0)

        # The following code is only for sample use
        return render_template('service-list.html', request, service_list=service_list)

    ### service invocation
    @routes.get('/invoke-service', name='invoke-service')
    async def invoke_service(request):
        return render_template('invoke-service.html', request)

    @routes.post('/exec/invoke-service')
    async def trigger_invocation(request):
        return redirect('invoke-service', request)

    ### access control
    @routes.get('/access-control', name='access-control')
    async def access_control(request):
        load = json.loads(json_format.MessageToJson(controller.access_list))
        if not load:
            service_prefix_list = []
        else:
            service_prefix_list = load["access"]
        # The following code is only for sample use
        return render_template('access-control.html', request, service_prefix_list=service_prefix_list)

    @routes.post('/exec/update-access-rights')
    async def update_access_rights(request):
        r_json = await request.json()
        print(r_json['prefix'])
        print(r_json['access_type'])
        return redirect('access-control', request)

    @routes.get('/ndn-ping')
    async def ndn_ping(request):
        return render_template('ndn-ping.html', request)

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
        web.run_app(app)
    finally:
        controller.save_db()


if __name__ == '__main__':
    app_main()
