import asyncio
import subprocess
import time
import os
import logging
from datetime import datetime
from ndniot.controller import Controller
from flask import Flask, redirect, render_template, request, url_for, jsonify
from flask_socketio import SocketIO
from pyndn import Interest, Data, NetworkNack
from google.protobuf import json_format
from PIL import Image
from pyzbar.pyzbar import decode
import json
from pyndn.util.blob import Blob
from pyndn.name import Name

def app_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG,
                        style='{')

    base_path = os.getcwd()
    # Serve static content from /static
    app = Flask(__name__,
                static_url_path='/static',
                static_folder=os.path.join(base_path, 'static'),
                template_folder=os.path.join(base_path, 'templates'))
    logging.info(os.path.join(base_path, 'templates'))

    app.config['SECRET_KEY'] = '3mlf4j8um6mg2-qlhyzk4ngxxk$8t4hh&$r)%968koxd3i(j#f'
    socketio = SocketIO(app, async_mode='threading')
    controller = Controller.start_controller(socketio.emit)

    def run_until_complete(event):
        asyncio.set_event_loop(asyncio.new_event_loop())
        return asyncio.get_event_loop().run_until_complete(event)

    @app.route('/')
    def index():
        if controller.networking_ready is not True:
            run_until_complete(controller.iot_connectivity_init())
        return render_template('index.html')

    @app.route('/system-overview')
    def system_overview():
        metainfo = []
        metainfo.append({"information":"System Prefix","value":controller.system_prefix})
        metainfo.append({"information":"System Anchor","value":controller.system_anchor.name.toUri()})
        if controller.device_list.IsInitialized() is True:
            metainfo.append({"information": "Available Devices", "value": str(len(controller.device_list.device))})
        if controller.service_list.IsInitialized() is True:
            metainfo.append({"information": "Available Services", "value": str(len(controller.service_list.service))})
        return render_template('system-overview.html', metainfo = metainfo)

    ### bootstrapping
    @app.route('/bootstrapping')
    def bootstrapping():
        load = json.loads(json_format.MessageToJson(controller.shared_secret_list))
        if not load:
            existing_shared_secrets = []
        else:
            existing_shared_secrets = load["sharedsecrets"]
        logging.info("bootstapping")
        logging.info(existing_shared_secrets)
        return render_template('bootstrapping.html',existing_shared_secrets = existing_shared_secrets)

    ### room
    @app.route('/room')
    def room():
        room_list = []
        return render_template("room.html",room_list= room_list)

    ### trigger bootstrapping process
    @app.route('/exec/bootstrapping', methods=['POST'])
    def bootstrap_device():
        r_json = request.get_json()
        #shared_secret = r_json['secret']
        ret = run_until_complete(controller.bootstrapping())
        logging.info("Bootstrap result:")
        logging.info(ret)
        return jsonify(ret)

    ###add shared_secrets
    @app.route('/add/shared_secrets',methods=['POST'])
    def add_shared_secrets():
        up_img = request.files['file']
        shared_info = json.loads(decode(Image.open(up_img))[0].data)
        new_shared_secret = controller.shared_secret_list.sharedsecrets.add()
        try:
            new_shared_secret.device_identifier = shared_info["device_identifier"]
            new_shared_secret.public_key = shared_info["public_key"]
            new_shared_secret.symmetric_key = shared_info["symmetric_key"]
            res = json.loads(json_format.MessageToJson(controller.shared_secret_list))
            res["st_code"] = 200
            return res
        except:
            return jsonify({"st_code":500})

    ###delete shared_secrets
    @app.route('/delete/shared_secrets',methods=['POST'])
    def delete_shared_secrets():
        r_json = request.get_json()
        try:
            count = 0
            for ss in controller.shared_secret_list.sharedsecrets:
                if ss.device_identifier == r_json["deviceIdentifier"] and \
                        ss.public_key == r_json["publicKey"] and \
                        ss.symmetric_key == r_json["symmetricKey"]:
                    del controller.shared_secret_list.sharedsecrets[count]
                count += 1
                return jsonify({"st_code": 200})
        except:
          return jsonify({"st_code": 500})


    ### device list
    @app.route('/device-list')
    def device_list():
        load = json.loads(json_format.MessageToJson(controller.device_list))
        if not load:
            device_list = []
        else:
            device_list = load["device"]
        # The following code is only for sample use
        return render_template('device-list.html', device_list=device_list)

    @app.route('/delete/device',methods=['POST'])
    def remove_device():
        r_json = request.get_json()
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
            return jsonify({"st_code": 500})
        # delete device identity in pib
        try:
            controller.keychain.deleteIdentity(Name(device_id_name))
        except:
            logging.error('Cannot find the pib-identity of the deleting device')
            return jsonify({"st_code": 500})
        # delete service information from leveldb
        # service Name: system_prefix/%01/<service-id>/ [Device Identifier]
        # Device Identifier should not start with '/'
        for service_name in list(controller.real_service_list.keys()):
            d_id = Name(service_name)[3:].__str__()[1:] #get rid of the beginning '/'; device id shall not start with '/'
            if d_id == r_json["device_id"]:
                del controller.real_service_list[service_name]
        return jsonify({"st_code": 200})



    ### service list
    @app.route('/service-list')
    def service_list():
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
        return render_template('service-list.html', service_list=service_list)

    ### service invocation
    @app.route('/invoke-service')
    def invoke_service():
        return render_template('invoke-service.html')

    @app.route('/exec/invoke-service', methods=['POST'])
    def trigger_invocation():
        return redirect(url_for('/invoke-service'))

    ### access control
    @app.route('/access-control')
    def access_control():
        load = json.loads(json_format.MessageToJson(controller.access_list))
        if not load:
            service_prefix_list = []
        else:
            service_prefix_list = load["access"]
        # The following code is only for sample use
        return render_template('access-control.html', service_prefix_list=service_prefix_list)

    @app.route('/exec/update-access-rights', methods=['POST'])
    def update_access_rights():
        r_json = request.get_json()
        print(r_json['prefix'])
        print(r_json['access_type'])
        return redirect(url_for('/access-control'))

    @app.route('/ndn-ping')
    def ndn_ping():
        return render_template('ndn-ping.html')

    @app.route('/exec/ndn-ping', methods=['POST'])
    def exec_ndn_ping():
        controller.decode_crypto_public_key(controller.get_crypto_public_key(controller.system_anchor))
        r_json = request.get_json()
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
        ret = run_until_complete(controller.express_interest(interest))
        ed_time = time.time()
        response_time = '{:.3f}s'.format(ed_time - st_time)
        print(response_time, ret)
        ret['response_time'] = response_time
        return jsonify(ret)

    ## NFD Management
    # @app.route('/nfd-management')
    # def nfd_management():
    #     nfd_state = server.connection_test()
    #     return render_template('nfd-management.html', nfd_state=nfd_state)


    # @app.route('/exec/start-nfd')
    # def start_nfd():
    #     subprocess.run('nfd-start')
    #     return redirect('/nfd-management')


    # @app.route('/exec/stop-nfd')
    # def stop_nfd():
    #     subprocess.run('nfd-stop')
    #     return redirect('/nfd-management')
    try:
        socketio.run(app, port=5001)
    finally:
        controller.save_db()

if __name__ == '__main__':
    app_main()
