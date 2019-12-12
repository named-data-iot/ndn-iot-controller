NDN IoT Controller
==================

This is a GUI controller for NDN-Lite empowered IoT system.
The controller runs on any platform that supports Python and Web service.

The controller is designed to control NDN IoT system in terms of
* GUI System overview.
* GUI Device Bootstrapping. This will add new devices into the system.
* GUI Trust Management. This includes credential issuance, revocation, and renew. (not finished)
* GUI Access Control. This includes access rights management among users, devices, and services. (not finished)
* GUI Service Management and service invocation. (not finished)

## Dependencies

#### 1. >Python 3.6

#### 2. zbar
If you are using MacOS:
```bash
brew install zbar
```

#### 3. leveldb
If you are using MacOS:
```bash
brew install leveldb
```

## Setup Development Environment

Python venv:
```bash
python3 -m venv ./venv
./venv/bin/python -m pip install -r requirements.txt
```

## Execute

Python server:
```bash
./venv/bin/python app.py
```