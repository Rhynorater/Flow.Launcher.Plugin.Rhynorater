# -*- coding: utf-8 -*-

import sys,os
parent_folder_path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(parent_folder_path)
sys.path.append(os.path.join(parent_folder_path, 'lib'))
sys.path.append(os.path.join(parent_folder_path, 'plugin'))

from flowlauncher import FlowLauncher
import webbrowser
import subprocess
import pyperclip
import re
from PIL import ImageGrab
import pytesseract
import base64
import urllib.parse
import hashlib
import json
import html
import xml.dom.minidom


class RhynoLauncher(FlowLauncher):
    
    # Configurable paths
    USER_PATH_WINDOWS = os.path.expanduser("~") + "\\"
    USER_PATH_LINUX = "/j/"
    TEMP_DIR = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")
    NOTEPADPP_PATH = r"C:\Program Files\Notepad++\notepad++.exe"
    IMHEX_PATH = r"C:\Program Files\ImHex\imhex.exe"
    TESSERACT_TEMP_IMG = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp", "tmpOcr.png")

    def __init__(self):
        self.query_handlers = [
            ('rhyhelp', self._handle_rhyhelp),
            ('cvss', self._handle_cvss), # Autolaunch
            ('pyd', self._handle_pyd), # Autolaunch
            ('cedit', self._handle_cedit), # Autolaunch
            ('chex', self._handle_chex), # Autolaunch
            ('cookie', self._handle_cookie),
            ('jwt', self._handle_jwt),
            ('ueall', self._handle_ueall),
            ('ocr', self._handle_ocr),
            ('convpath', self._handle_convpath),
            ('mrr', self._handle_mrr), #Must be above mr
            ('mr', self._handle_mr),
            ('mdr', self._handle_mdr), #Must be above md
            ('md', self._handle_md)
        ]
        self.special_handlers = [
            (self._is_transform_query, self._handle_transforms),
            (self._is_quoted_query, self._handle_quoted_string),
        ]
        super().__init__()

    def _create_default_response(self, title, subtitle, method="noop", params=None):
        return {
            "Title": title,
            "SubTitle": subtitle,
            "IcoPath": "Images/app.png",
            "JsonRPCAction": {
                "method": method,
                "parameters": params or []
            }
        }

    def noop(self):
        return 

    def _is_transform_query(self, query):
        return all(c in "qwaszxercv" for c in query.strip())
    
    def _is_quoted_query(self, query):
        return query.startswith('"') and query.endswith('"')

    def query(self, query):
        for prefix, handler in self.query_handlers:
            if query.startswith(prefix):
                return handler(query)

        for condition, handler in self.special_handlers:
            if condition(query):
                return handler(query)
        
        return []

    def _handle_rhyhelp(self, query):
        help_data = [
            {
                "title": "RhynoLauncher Help",
                "subtitle": "The following commands are available:"
            },
            {
                "title": "cvss",
                "subtitle": "Description: Opens cvssadvisor.com. Example: cvss"
            },
            {
                "title": "pyd",
                "subtitle": "Description: Opens a WSL python3 console. Example: pyd"
            },
            {
                "title": "cedit",
                "subtitle": "Description: Opens clipboard content in Notepad++. Example: cedit"
            },
            {
                "title": "chex",
                "subtitle": "Description: Opens clipboard content in ImHex. Example: chex"
            },
            {
                "title": "cookie",
                "subtitle": "Description: Replaces `Cookie:.*` with `Cookie: {YOUR COOKIES}` in clipboard. Example: cookie"
            },
            {
                "title": "ueall <string>",
                "subtitle": "Description: URL encodes all characters in the string. Example: ueall 'hello world'"
            },
            {
                "title": "jwt <token>",
                "subtitle": "Description: Decodes a JWT token using jwt.io. Example: jwt ey..."
            },
            {
                "title": "ocr",
                "subtitle": "Description: OCR on image in clipboard. Example: ocr"
            },
            {
                "title": "convpath",
                "subtitle": "Description: Converts path in clipboard (Win <-> Linux). Example: convpath"
            },
            {
                "title": "mr <find> <replace>",
                "subtitle": "Description: Match and replace in clipboard. Example: mr 'foo' 'bar'"
            },
            {
                "title": "mrr <regex> <replace>",
                "subtitle": r"Description: Regex match and replace in clipboard. Example: mrr '\\s+' ' '"
            },
            {
                "title": "mdr <regex>",
                "subtitle": r"Description: Regex match and delete in clipboard. Example: mdr '\\s+'"
            },
            {
                "title": "md <string>",
                "subtitle": "Description: Match and delete string from clipboard. Example: md 'remove'"
            },
            {
                "title": "Transforms (q,w,a,s,z,x,e,r,c,v)",
                "subtitle": "q:urlenc, w:urldec, a:b64enc, s:b64dec, z:json pretty, x:json-minify, e:htmlenc, r:htmldec, c:xml pretty, v:xml-minify. Ex: 'qac' on clipboard"
            },
            {
                "title": "\"...\"",
                "subtitle": "Description: Info about a string (counts, hashes, etc). Example: \"hello world\""
            }
        ]
        
        return [self._create_default_response(item["title"], item["subtitle"]) for item in help_data]

    def _handle_jwt(self, query):
        token = query.split(" ")[-1]
        return [self._create_default_response(
            f"jwt.io: {query}",
            "Load this shit into JWT.io",
            "open_url",
            [f"https://jwt.io/#token={token}"]
        )]

    def _handle_ueall(self, query):
        if query.startswith("ueall "):
            text_to_encode = query[len("ueall "):]
            encoded_text = "".join(f"%{c:02x}" for c in text_to_encode.encode('utf-8'))
            return [self._create_default_response(
                "URL Encode All",
                encoded_text,
                "copy",
                [encoded_text]
            )]
        return [self._create_default_response(
            "URL Encode All",
            "Type a string to URL encode (all characters)."
        )]

    def _handle_cvss(self, query):
        self.open_url("https://cvssadvisor.com")
        return []

    def _handle_ocr(self, query):
        return [self._create_default_response(
            "Clipboard OCR",
            "Copy the contents of the image in your clipboard to your clipboard via ocr.",
            "clipOCR"
        )]

    def _handle_convpath(self, query):
        cb = pyperclip.paste().lower()
        if cb.startswith(self.USER_PATH_WINDOWS):
            converted = cb.replace(self.USER_PATH_WINDOWS, self.USER_PATH_LINUX).replace("\\", "/")
            return [self._create_default_response(
                "Convert Path (Windows -> Linux)",
                f"{cb} => {converted}",
                "copy",
                [converted]
            )]
        elif cb.startswith(self.USER_PATH_LINUX):
            converted = cb.replace(self.USER_PATH_LINUX, self.USER_PATH_WINDOWS).replace("/", "\\")
            return [self._create_default_response(
                "Convert Path (Linux -> Windows)",
                f"{cb} => {converted}",
                "copy",
                [converted]
            )]
        return []

    def _handle_pyd(self, query):
        subprocess.call("wsl python3", creationflags=subprocess.CREATE_NEW_CONSOLE)
        return []

    def _handle_mr(self, query):
        parts = query.split(" ")
        if len(parts) == 3 and parts[0] == "mr":
            match_str, replace_str = parts[1], parts[2]
            return [self._create_default_response(
                "Match & Replace",
                f"Match {match_str} and replace with {replace_str}",
                "clipMAndR",
                [match_str, replace_str]
            )]
        return [self._create_default_response(
            "Match & Replace",
            "Match & Replace what is in your clipboard."
        )]

    def _handle_mrr(self, query):
        parts = query.split(" ")
        if len(parts) == 3 and parts[0] == "mrr":
            match_str, replace_str = parts[1], parts[2]
            return [self._create_default_response(
                "Match & Replace (Regex)",
                f"Match {match_str} and replace with {replace_str}",
                "clipMAndRRegex",
                [match_str, replace_str]
            )]
        return [self._create_default_response(
            "Match & Replace (Regex)",
            "Match & Replace what is in your clipboard."
        )]

    def _handle_md(self, query):
        parts = query.split(" ")
        if len(parts) == 2 and parts[0] == "md":
            return [self._create_default_response(
                "Match & Delete",
                f"Remove {parts[1]} from clipboard string.",
                "clipMAndD",
                [parts[1]]
            )]
        return [self._create_default_response(
            "Match & Delete",
            "Match & Delete strings from your clipboard."
        )]

    def _handle_mdr(self, query):
        parts = query.split(" ")
        if len(parts) == 2 and parts[0] == "mdr":
            return [self._create_default_response(
                "Match & Delete (Regex)",
                f"Remove {parts[1]} from clipboard string.",
                "clipMAndDRegex",
                [parts[1]]
            )]
        return [self._create_default_response(
            "Match & Delete (Regex)",
            "Match & Delete strings from your clipboard."
        )]

    def _html_encode_all_special(self, text):
        return "".join(c if c.isalnum() or c.isspace() else f"&#x{hex(ord(c))[2:]};" for c in text)

    def _tolerant_b64decode(self, text):
        padding = len(text) % 4
        if padding:
            text += '=' * (4 - padding)
        return base64.b64decode(text).decode('utf-8')

    def _handle_transforms(self, query):
        d = pyperclip.paste()
        transformations = {
            'q': lambda text: urllib.parse.quote(text, safe=""),
            'w': lambda text: urllib.parse.unquote(text),
            'a': lambda text: base64.b64encode(text.encode("utf-8")).decode(),
            's': self._tolerant_b64decode,
            'z': lambda text: json.dumps(json.loads(text), indent=2),
            'x': lambda text: json.dumps(json.loads(text)),
            'e': self._html_encode_all_special,
            'r': lambda text: html.unescape(text),
            'c': lambda text: xml.dom.minidom.parseString(text).toprettyxml(indent="  "),
            'v': lambda text: re.sub(r'>\s*<', '><', text.replace('\n', ' ').replace('\r', ' ')).strip()
        }
        
        for char in query.strip():
            if char in transformations:
                try:
                    d = transformations[char](d)
                except Exception:
                    # Silently fail on transform error, keeping previous data
                    pass
        
        return [self._create_default_response(
            "Text Modification",
            f"Data: {d}",
            "copy",
            [d]
        )]
    
    def _handle_cedit(self, query):
        cb = pyperclip.paste()
        temp_file = os.path.join(self.TEMP_DIR, "temp.txt")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(cb)
        subprocess.Popen([self.NOTEPADPP_PATH, temp_file])
        return [self._create_default_response(
            "Edit in Notepad++",
            f"Opened {temp_file} in Notepad++"
        )]

    def _handle_chex(self, query):
        cb = pyperclip.paste()
        temp_file = os.path.join(self.TEMP_DIR, "temp.bin")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(cb)
        subprocess.Popen([self.IMHEX_PATH, temp_file])
        return [self._create_default_response(
            "Hex Editor",
            f"Opened {temp_file} in ImHex"
        )]

    def _handle_cookie(self, query):
        return [self._create_default_response(
            "Anonymize Cookie",
            "Replaces `Cookie:` header in clipboard with a placeholder.",
            "clipCookie"
        )]

    def _handle_quoted_string(self, query):
        content = query[1:-1]
        content_bytes = content.encode("utf-8")
        
        # Generate unicode codepoints in u0000 syntax
        unicode_codepoints = " ".join(f"u{ord(char):04x}" for char in content)
        
        res = [
            self._create_default_response("Char Count (not including \"s)", str(len(content))),
            self._create_default_response("Word Count (not including \"s)", str(len(list(filter(None, content.split(" ")))))),
            self._create_default_response("Unicode Codepoints", unicode_codepoints, "copy", [unicode_codepoints]),
            self._create_default_response("Hex", content_bytes.hex(), "copy", [content_bytes.hex()]),
            self._create_default_response("MD5", hashlib.md5(content_bytes).hexdigest(), "copy", [hashlib.md5(content_bytes).hexdigest()]),
            self._create_default_response("SHA256", hashlib.sha256(content_bytes).hexdigest(), "copy", [hashlib.sha256(content_bytes).hexdigest()]),
            self._create_default_response("SHA1", hashlib.sha1(content_bytes).hexdigest(), "copy", [hashlib.sha1(content_bytes).hexdigest()]),
        ]

        try:
            d = content.lower()
            if d.startswith("0x"):
                d = d[2:]
            decoded_hex = bytearray.fromhex(d).decode()
            res.insert(2, self._create_default_response("Hex Decoding", decoded_hex, "copy", [decoded_hex]))
        except (ValueError, UnicodeDecodeError):
            pass
            
        return res

    def context_menu(self, data):
        return [
            {
                "Title": "RhynoLauncher",
                "SubTitle": "Press enter to open Flow the plugin's repo in GitHub",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "open_url",
                    "parameters": ["https://github.com/Flow-Launcher/Flow.Launcher.Plugin.RhynoLauncherPython"]
                }
            }
        ]

    def clipOCR(self):
        img = ImageGrab.grabclipboard()
        if img:
            img.save(self.TESSERACT_TEMP_IMG)
            self.copy(pytesseract.image_to_string(self.TESSERACT_TEMP_IMG))

    def clipMAndR(self, m, r):
        d = pyperclip.paste()
        if m == "\\n":
            m = "\n"
            d = d.replace("\r", "")
        d = d.replace(m, r)
        pyperclip.copy(d)

    def clipMAndRRegex(self, m, r):
        d = pyperclip.paste()
        d = re.sub(m,r,d)
        pyperclip.copy(d)
    
    def clipMAndD( self, m):
        d = pyperclip.paste()
        d = d.replace(m, "")
        pyperclip.copy(d)
    
    def clipMAndDRegex(self, m):
        d = pyperclip.paste()
        d = re.sub(m, "", d)
        pyperclip.copy(d)

    def clipCookie(self):
        d = pyperclip.paste()
        d = re.sub(r"Cookie:.*", "Cookie: {YOUR COOKIES}", d, flags=re.IGNORECASE)
        pyperclip.copy(d)

    def copy( self, d):
        pyperclip.copy(d)

    def open_url(self, url):
        webbrowser.open(url)

if __name__ == "__main__":
    RhynoLauncher()
