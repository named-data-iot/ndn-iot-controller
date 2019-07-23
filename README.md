NDN IoT Controller
==================

This is a GUI controller for NDN-Lite empowered IoT system.
The controller runs on any platform that supports Python and Web service.

The controller is designed to control NDN IoT system in terms of
* GUI System overview.
* GUI Device Bootstrapping. This will add new devices into the system.
* GUI Trust Management. This includes credential issuance, revocation, and renew.
* GUI Access Control. This includes access rights management among users, devices, and services.
* GUI Service Management and service invocation.

This project was greatly inspired by the NDN-CC (https://github.com/zjkmxy/ndn-cc) project.
We thank Xinyu Ma, Zhaoning Kong, and Zhiyi Zhang for their contribution to NDN-CC project.

## Dependencies

- Python 3.6
- NodeJS (optional)

## Setup Development Environment

Python venv:
```bash
python3 -m venv ./venv
./venv/bin/python -m pip install -r requirements.txt
```

Electron:
```bash
npm install
```

## Execute

Electron:
```bash
npm start
```

Python server:
```bash
./venv/bin/python app.py
```