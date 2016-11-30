#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""Proxy Registrar."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import sys
import socketserver


class ConfigHandler(ContentHandler):
    """For handling Configuration entries"""

    def __init__(self):
        """Constructor. Inicializamos las variables"""
        self.myconfig = []

    def startElement(self, element, attr):
        """Método que se llama cuando se abre una etiqueta"""
        if element == "server":       # one way to do it
            name = attr.get('name', "")
            if name == "":
                name = "ProxyServerDefaultName"
            self.myconfig.append(name)
            ip = attr.get('ip', "")
            if ip == "":
                ip = "127.0.0.1"
            self.myconfig.append(ip)
            puerto = attr.get('puerto', "")
            self.myconfig.append(puerto)
        elif element == "database":
            path = attr.get('path', "")
            self.myconfig.append(path)
            passwdpath = attr.get('path', "")
            self.myconfig.append(passwdpath)
        elif element == 'log':
            path = attr.get('path', "")
            self.myconfig.append(path)
    
    def get_config(self):
        return self.myconfig

class SIPHandler(socketserver.DatagramRequestHandler):
    """Main handler to send a RTP audio stream."""

    def handle(self):
        """Handler to manage incoming users SIP request."""
        line = self.rfile.read()
        line_str = line.decode('utf-8')
        if line_str.split(" ")[0] == "REGISTER":
            self.wfile.write(b"SIP/2.0 401 Unauthorized\r\n\r\n")
        if line_str.split(" ")[0] == "INVITE":
            self.wfile.write(b"SIP/2.0 100 Trying\r\n\r\n")
            self.wfile.write(b"SIP/2.0 180 Ringing\r\n\r\n")
            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
        elif line_str.split(" ")[0] == "ACK":
            send = "mp32rtp -i 127.0.0.1 -p 23032 < " + sys.argv[3]
            os.system(send)
        elif line_str.split(" ")[0] == "BYE":
            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
        elif line_str.split(" ")[0] != "":
            if line_str.split(" ")[0] == "invite" or\
               line_str.split(" ")[0] == "bye":  # Avoiding lower cases methods
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
            else:
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")
        print(line_str)

def actual_time():
    timenow = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
    return timenow

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
        if len(sys.argv) != 2:
            raise IndexError
        parser = make_parser()
        cHandler = ConfigHandler()
        parser.setContentHandler(cHandler)
        parser.parse(open(CONFIG))
        config = cHandler.get_config()
        serv = socketserver.UDPServer((config[1], int(config[2])), SIPHandler)
        print("Server " + config[0] + " listening at port " + config[2] +
              "...")
        serv.serve_forever()
    except (IndexError, ValueError):
        sys.exit("Usage: python proxy_registrar.py config")
    except KeyboardInterrupt:
        print("END OF SERVER")