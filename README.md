NDN IoT Controller
==================
This is a GUI controller for NDN-Lite empowered system.
The controller runs on any platform that supports Python and Web service.

This project was greatly inspired by the NDN-CC project.

##Dependencies

- Python 3.6
- NodeJS (optional)

##Setup Development Environment

Python venv:
```bash
python3 -m venv ./venv
./venv/bin/python -m pip install -r requirements.txt
```

Electron:
```bash
npm install
```

##Execute

Electron:
```bash
npm start
```

Python server:
```bash
./venv/bin/python app.py
```