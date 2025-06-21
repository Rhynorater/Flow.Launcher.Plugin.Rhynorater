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


class RhynoLauncher(FlowLauncher):
    def noop():
        return 

    def matchAndReplace(self, query):
        if query == "mr ":
            return [{
                "Title": "Match & Replace",
                "SubTitle": "Match & Replace what is in your clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]
        pq = query.split(" ")
        if len(pq) == 3:
            return [{
                "Title": "Match & Replace",
                "SubTitle": f"Match {pq[1]} and replace with {pq[2]}",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "clipMAndR",
                    "parameters": [pq[1], pq[2]]
                }
            }]
        
        return [{
                "Title": "Match & Replace",
                "SubTitle": "Match & Replace what is in your clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]

    def matchAndReplaceRegex(self, query):
        if query == "mr ":
            return [{
                "Title": "Match & Replace (Regex)",
                "SubTitle": "Match & Replace what is in your clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]
        pq = query.split(" ")
        if len(pq) == 3:
            return [{
                "Title": "Match & Replace (Regex)",
                "SubTitle": f"Match {pq[1]} and replace with {pq[2]}",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "clipMAndRRegex",
                    "parameters": [pq[1], pq[2]]
                }
            }]
        
        return [{
                "Title": "Match & Replace (Regex)",
                "SubTitle": "Match & Replace what is in your clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]

    def matchAndDelete(self, query):
        if query == "md ":
            return [{
                "Title": "Match & Delete",
                "SubTitle": "Match & Delete strings from you clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]
        pq = query.split(" ")
        if len(pq) == 2:
            return [{
                "Title": "Match & Delete",
                "SubTitle": f"Remove {pq[1]} from clipboard string.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "clipMAndD",
                    "parameters": [pq[1]]
                }
            }]
        
        return [{
                "Title": "Match & Delete",
                "SubTitle": "Match & Delete strings from you clipboard.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            }]


    def query(self, query):
        if query.startswith("jwt "):
            return [
            {
                "Title": "jwt.io: "+query,
                "SubTitle": "Load this shit into JWT.io",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "open_url",
                    "parameters": ["https://jwt.io/#token="+ query.split(" ")[-1]]
                }
            }
        ]
        elif query.startswith("cvss"):
            self.open_url("https://cvssadvisor.com")
        elif query.startswith("ocr"):
            return [{
                "Title": "Clipboard OCR",
                "SubTitle": "Copy the contents of the image in your clipboard to your clipboard via ocr.",
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "clipOCR",
                    "parameters": []
                }
            }] 
        elif query.startswith("convpath"):
            cb = pyperclip.paste().lower()
            if cb.startswith("c:\\users\\justin"):
                return [{
                    "Title": "Convert Path (Windows -> Linux)",
                    "SubTitle": cb+" => "+cb.replace("c:\\users\\justin\\", "/j/").replace("\\", "/"),
                    "IcoPath": "Images/app.png",
                    "JsonRPCAction": {
                        "method": "copy",
                        "parameters": [cb.replace("c:\\users\\justin\\", "/j/").replace("\\", "/")]
                    }}]
            elif cb.startswith("/j/"):
                return [{
                        "Title": "Convert Path (Linux -> Windows)",
                        "SubTitle": cb+" => "+cb.replace("/j/", "c:\\users\\justin\\").replace("/", "\\"),
                        "IcoPath": "Images/app.png",
                        "JsonRPCAction": {
                            "method": "copy",
                            "parameters": [cb.replace("/j/", "c:\\users\\justin\\").replace("/", "\\")]
                        }
                    }]
        elif query.startswith("pyd"):
            subprocess.call("wsl python3", creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif all(map(lambda j: j in ["q","w","a","s","z","x"], list(query))):
            # q - url encode
            # w - url decode
            # a - base64 encode
            # s - base64 decode
            # z - json prettify
            # x - json minify
            d = pyperclip.paste()
            query = query.strip() 
            for l in list(query):
                
                if l == "q":
                    d = urllib.parse.quote(d)
                elif l == "w":
                    d = urllib.parse.unquote(d)
                elif l == "a":
                    d = base64.b64encode(d.encode("utf-8")).decode()
                elif l == "s":
                    d = base64.b64decode(d.encode("utf-8")).decode()
                elif l == "z":
                    d = json.dumps(json.loads(d), indent=2)
                elif l == "x":
                    d = json.dumps(json.loads(d))
            return [{
            "Title": "Text Modification",
            "SubTitle": "Data: "+d,
            "IcoPath": "Images/app.png",
            "JsonRPCAction": {
                "method": "copy",
                "parameters": [d]
                }
            }]
        elif query.startswith("mrr"):
            return self.matchAndReplaceRegex(query)
        elif query.startswith("md"):
            return self.matchAndDelete(query)    
        elif query.startswith("mr"):
            return self.matchAndReplace(query)
        elif query.startswith("\"") and query.endswith("\""):
            md5 = hashlib.md5()
            md5.update(query[1:-1].encode("utf-8"))
            md5= md5.hexdigest()
            sha256 = hashlib.sha256()
            sha256.update(query[1:-1].encode("utf-8"))
            sha256 = sha256.hexdigest()
            sha1 = hashlib.sha1()
            sha1.update(query[1:-1].encode("utf-8"))
            sha1 = sha1.hexdigest()
            res =  [{
                "Title": "Char Count (not including \"s)",
                "SubTitle": str(len(query[1:-1])),
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            },{
                "Title": "Word Count (not including \"s)",
                "SubTitle": str(len(list(filter(lambda x: x, query[1:-1].split(" "))))),
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "noop",
                    "parameters": []
                }
            },{
                "Title": "Hex",
                "SubTitle": query[1:-1].encode("utf-8").hex(),
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "copy",
                    "parameters": [query[1:-1].encode("utf-8").hex()]
                }
            },{
                "Title": "MD5",
                "SubTitle": md5,
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "copy",
                    "parameters": [md5]
                }
            },{
                "Title": "SHA256",
                "SubTitle": sha256,
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "copy",
                    "parameters": [sha256]
                }
            },{
                "Title": "SHA1",
                "SubTitle": sha1,
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "copy",
                    "parameters": [sha1]
                }
            }]

            try:
                d = query[1:-1].lower()
                if d.startswith("0x"):
                    d = d[2:]
                d = bytearray.fromhex(d).decode()
                res.insert(2, {
                "Title": "Hex Decoding",
                "SubTitle": d,
                "IcoPath": "Images/app.png",
                "JsonRPCAction": {
                    "method": "copy",
                    "parameters": [d]
                }
                })
            except:
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
            img.save("C:\\Users\\Justin\\AppData\\Local\\Temp\\tmpOcr.png")
            self.copy(pytesseract.image_to_string('C:\\Users\\Justin\\AppData\\Local\\Temp\\tmpOcr.png'))


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

    def copy( self, d):
        pyperclip.copy(d)

    def open_url(self, url):
        webbrowser.open(url)

if __name__ == "__main__":
    RhynoLauncher()
