import asyncio
import subprocess
import time
import os
import logging
from datetime import datetime
from ndniot.controller import Controller
from flask import Flask, redirect, render_template, request, url_for
from flask_socketio import SocketIO
from pyndn import Interest, Data, NetworkNack

def app_main():
    logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.INFO,
                        style='{')

    base_path = os.getcwd()
    # Serve static content from /static
    app = Flask(__name__,
                static_url_path='/static',
                static_folder=os.path.join(base_path, 'static'),
                template_folder=os.path.join(base_path, 'templates'))

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
        metainfo = {}
        metainfo["system_prefix"] = controller.system_prefix
        metainfo["system_anchor"] = controller.system_anchor.name.toUri()
        if controller.device_list.IsInitialized() is True:
            metainfo["available_devices"] = str(len(controller.device_list.device))
        if controller.service_list.IsInitialized() is True:
            metainfo["available_services"] = str(len(controller.service_list.service))
        return render_template('system-overview.html', metainfo = metainfo)

    ### bootstrapping
    @app.route('/bootstrapping')
    def bootstrapping():
        return render_template('bootstrapping.html')

    ### trigger bootstrapping process
    @app.route('/exec/bootstrapping', methods=['POST'])
    def bootstrap_device():
        shared_secret = request.form['secret']
        ret = None # run_until_complete(server.bootstrap_device(shared_secret))
        if ret is None:
            logging.info("No response: device bootstrapping")
        else:
            logging.info("Bootstrap device")
        return redirect(url_for('device_list'))

    ### device list
    @app.route('/device-list')
    def device_list():
        device_list= controller.get_devices()
        # The following code is only for sample use
        # device_list=[
        #     {
        #         "device_name": "/myhome/bedroom/light-0-1",
        #         "device_info": "Philips LED light"
        #     },
        #     {
        #         "device_name": "/myhome/livingroom/printer-A",
        #         "device_info": "HP Printer X580"
        #     }
        # ]
        # Sample code end. Delete the code when in real development
        return render_template('device-list.html', device_list=device_list)

    @app.route('/exec/remove_device')
    def remove_device():
        device_name=request.form["device_name"]
        ret = "" # run_until_complete(server.invoke_cert(device_name))
        return render_template('face-list.html', device_list=device_list)

    ### service list
    @app.route('/service-list')
    def service_list():
        service_list = controller.get_services()
        # The following code is only for sample use
        service_list=[
            {
                "service_id": "printer",
                "service_info": "Printer Control",
                "available_commands": "start, print, restart, halt"
            },
            {
                "service_id": "LED",
                "service_info": "LED Light Control",
                "available_commands": "on, off"
            }
        ]
        # Sample code end. Delete the code when in real development
        fields = list(['service_id','service_info','available_commands'])
        fields_collapse = [field for field in set(fields) - {'service_id'}]
        return render_template('service-list.html', service_list=service_list,
                               fields_collapse=fields_collapse)

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
        service_prefix_list = controller.access_list
        # The following code is only for sample use
        # service_prefix_list=[
        #     {
        #         "prefix": "/myhome/(ALL/)SD/printer",
        #         "access_type": "Controller Only",
        #     },
        #     {
        #         "prefix": "/myhome/livingroom/(ALL/)SD/printer",
        #         "access_type": "Controller Only",
        #     },
        #     {
        #         "prefix": "/myhome/livingroom/printer-A/SD/printer",
        #         "access_type": "Controller Only",
        #     },
        #     {
        #         "prefix": "/myhome/(ALL/)SD/LED",
        #         "access_type": "Controller Only",
        #     },
        #     {
        #         "prefix": "/myhome/bedroom(ALL/)/SD/LED",
        #         "access_type": "Controller Only",
        #     },
        #     {
        #         "prefix": "/myhome/bedroom/light-0-1/SD/LED",
        #         "access_type": "Controller Only",
        #     }
        # ]
        # Sample code end. Delete the code when in real development
        return render_template('access-control.html', service_prefix_list=service_prefix_list)

    @app.route('/exec/update-access-rights', methods=['POST'])
    def update_access_rights():
        return redirect(url_for('/access-control'))

    @app.route('/ndn-ping')
    def ndn_ping():
        return render_template('ndn-ping.html')

    @app.route('/exec/ndn-ping', methods=['POST'])
    def exec_ndn_ping():
        name = request.form['name']
        can_be_prefix = request.form['can_be_prefix'] == 'true'
        must_be_fresh = request.form['must_be_fresh'] == 'true'
        try:
            interest_lifetime = float(request.form['interest_lifetime']) * 1000.0
        except ValueError:
            interest_lifetime = 4000.0

        interest = Interest(name)
        interest.canBePrefix = can_be_prefix
        interest.mustBeFresh = must_be_fresh
        interest.interestLifetimeMilliseconds = interest_lifetime
        st_time = time.time()
        ret = run_until_complete(controller.express_interest(interest))
        ed_time = time.time()
        response_time = '{:.3f}s'.format(ed_time - st_time)
        return render_template('ndn-ping.html', response_time=response_time, **ret)

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

    socketio.run(app, port=5001)

if __name__ == '__main__':
    app_main()
