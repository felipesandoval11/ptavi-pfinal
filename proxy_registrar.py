#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""Proxy Registrar that serves as a middle term in a SIP/RTP connection."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import sys
import socketserver
import random


class ConfigHandler(ContentHandler):
    """For handling configuration entries."""

    def __init__(self):
        """My list of configurations."""
        self.myconfig = []

    def startElement(self, element, attr):
        """Method to save attributes."""
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
        """Return a configuration list for my purposes."""
        return self.myconfig

class SIPHandler(socketserver.DatagramRequestHandler):
    """Main handler of SIP responses."""

    def handle(self):
        """Handler to manage incoming users SIP request."""
        line = self.rfile.read()
        line_str = line.decode('utf-8')

        if line_str.split(" ")[0] == "REGISTER":
            if "Digest" not in line_str.split(" "):
                nonce = str(random.randint(000000000000000000000, 
                                           999999999999999999999))
            
                self.wfile.write(b"SIP/2.0 401 Unauthorized\r\n\r\n")
                self.wfile.write(bytes("WWW Authenticate: Digest nonce=" + 
                                       nonce + "\r\n", 'utf-8'))
            else:
            # Making my users text file
                user = line_str.split(":")[1]
                port = line_str.split(":")[2].split(" ")[0]
                expire = line_str.split(" ")[3].split("\r\n")[0]
                reg_time = time.strftime("%Y-%m-%d %H:%M:%S", 
                                         time.gmtime(time.time()))
                registered = user + " 127.0.0.1 " + port + " " + reg_time +\
                             " " + expire + "\n"
            # Making my users text file
                try:
                    users_file = open(config[3])
                    users_file = open(config[3], "a")
                    users_file.write(registered)
                except FileNotFoundError:   #  When the file does not exists.
                    users_file = open(config[3], "w") 
                    users_file.write(registered)
        elif line_str.split(" ")[0] == "INVITE":
            self.wfile.write(b"SIP/2.0 100 Trying\r\n\r\n")
            self.wfile.write(b"SIP/2.0 180 Ringing\r\n\r\n")
            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
        elif line_str.split(" ")[0] == "ACK":
            #send = "mp32rtp -i 127.0.0.1 -p 23032 < " + sys.argv[3]
            #os.system(send)
            print("AHORA ENVIO")
        elif line_str.split(" ")[0] == "BYE":
            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
        elif line_str.split(" ")[0] != "":
            if line_str.split(" ")[0] == "register" or\
               line_str.split(" ")[0] == "invite" or\
               line_str.split(" ")[0] == "bye":  # Avoiding lower cases methods
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
            else:
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")
        print("-- RECIEVED REQUEST --\r\n" + line_str)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       


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
        try:
            log_file = open(config[-1])
            log_file = open(config[-1], "a")
        except FileNotFoundError:   #  When the file does not exists.
            print("aqui")
            log_file = open(config[-1], "w")
            log_file.write(str(actual_time()) + " Starting...\n")
        serv = socketserver.UDPServer((config[1], int(config[2])), SIPHandler)
        print("Server " + config[0] + " listening at port " + config[2] +
              "...\n")
        serv.serve_forever()
    except (IndexError, ValueError):
        sys.exit("Usage: python proxy_registrar.py config")
    except KeyboardInterrupt:
        log_file.write(str(actual_time()) + " Finishing.\n")
        log_file.close
        print("END OF SERVER")
