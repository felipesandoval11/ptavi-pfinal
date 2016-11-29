#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""UDP Client Program that sends a SIP method request."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import sys


try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    if len(sys.argv) == 4:
        OPTION = sys.argv[3]
    elif len(sys.argv) != 3:
        raise IndexError
    if METHOD == "ACK":     # Por seguridad.
        raise ValueError
except (IndexError, ValueError):
    sys.exit("Usage: python uaclient.py config method option")

class ConfigHandler(ContentHandler):
    """For handling Configuration entries"""

    def __init__(self):
        """Constructor. Inicializamos las variables"""
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


if __name__ == "__main__":
    try:
        parser = make_parser()
        cHandler = ConfigHandler()
        parser.setContentHandler(cHandler)
        parser.parse(open(CONFIG))
        config = cHandler.get_config()
        # Content to send.
        SIP_LINE = METHOD + " sip:" + config[0] + " SIP/2.0\r\n\r\n"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((config[5], int(config[6])))
            print(SIP_LINE)
            my_socket.send(bytes(SIP_LINE, 'utf-8'))
            data = my_socket.recv(1024)
            print('-- RECIEVED SIP INFO --\n' + data.decode('utf-8'))
            if data.decode('utf-8').split(" ")[-1] == "OK\r\n\r\n" and \
               METHOD != "BYE":
                SIP_ACK = "ACK" + " sip:" + LOGIN + " SIP/2.0\r\n\r\n"
                my_socket.send(bytes(SIP_ACK, 'utf-8'))
                data = my_socket.recv(1024)
                print(data.decode('utf-8'))
            my_socket.close()
            print("END OF SOCKET")
    except ConnectionRefusedError:
        print("Connection Refused: Server not found.")
