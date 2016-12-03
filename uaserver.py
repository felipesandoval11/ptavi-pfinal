#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""UA Server Program that uses SIP and send a mp3 song via RTP"""

import socketserver
import sys
import os
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


class ConfigHandler(ContentHandler):
    """For handling Configuration entries"""

    def __init__(self):
        """Making a list with my configuration"""
        self.myconfig = []

    def startElement(self, name, attr):
        """Método que se llama cuando se abre una etiqueta"""
        if name == "account":       # one way to do it
            username = attr.get('username', "")
            self.myconfig.append(username)
            passwd = attr.get('passwd', "")
            self.myconfig.append(passwd)
        elif name == "uaserver":
            ip = attr.get('ip', "")
            self.myconfig.append(ip)
            puerto = attr.get('puerto', "")
            self.myconfig.append(puerto)
        elif name == 'rtpaudio':
            puerto_rtp = attr.get('puerto', "")
            self.myconfig.append(puerto_rtp)
        elif name == 'regproxy':
            ipproxy = attr.get('ip', "")
            self.myconfig.append(ipproxy)
            puerto_proxy = attr.get('puerto', "")
            self.myconfig.append(puerto_proxy)
        elif name == 'log':
            path = attr.get('path', "")
            self.myconfig.append(path)
        elif name == 'audio':
            path_audio = attr.get('path', "")
            self.myconfig.append(path_audio)

    def get_config(self):
        return self.myconfig

  
class SIPHandler(socketserver.DatagramRequestHandler):
    """Main handler to send a RTP audio stream."""

    def handle(self):
        """Handler to manage users SIP request."""
        line = self.rfile.read()
        line_str = line.decode('utf-8')
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
    """Format time YYYYMMDDHHMMSS for log purposes."""
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
        if not os.path.exists(config[-1]):  # Does this audio file exists?
            raise OSError
        serv = socketserver.UDPServer((config[2], int(config[3])), SIPHandler)
        print("Listening...")
        serv.serve_forever()
    except (IndexError, ValueError, OSError):
        sys.exit("Usage: python uaserver.py config")
    except KeyboardInterrupt:
        print("END OF SERVER")
