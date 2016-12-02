#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""UA Client Program that sends SIP methods request."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import socket
import sys
import random


try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    if len(sys.argv) == 4:
        OPTION = sys.argv[3]
    elif len(sys.argv) != 3 or METHOD == "ACK":
        raise IndexError
    if METHOD == "ACK":     # Por seguridad.
        raise ValueError
except (IndexError, ValueError):
    sys.exit("Usage: python uaclient.py config method option")


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
            if ip == "":
                ip = "127.0.0.1"
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


def actual_time():
    """Format time YYYYMMDDHHMMSS for log purposes."""
    timenow = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
    return timenow

if __name__ == "__main__":
    try:
        parser = make_parser()
        cHandler = ConfigHandler()
        parser.setContentHandler(cHandler)
        parser.parse(open(CONFIG))
        config = cHandler.get_config()
        try:
            log_file = open(config[7])
            log_file = open(config[7], "a")
        except FileNotFoundError:   #  When the file does not exists.
            log_file = open(config[7], "w")
            log_file.write(str(actual_time()) + " Starting...\n")
# Different kind of methods.
        if METHOD == "REGISTER":
            if len(sys.argv) == 4:
                SIP_LINE = METHOD + " sip:" + config[0] + ":" +\
                           config[3] + " SIP/2.0\r\n\r\n" + "Expires: " +\
                           OPTION + "\r\n"
            else:
                SIP_LINE = METHOD + " sip:" + config[0] + ":" +\
                           config[3] + " SIP/2.0\r\n\r\n" + "Expires: " +\
                           "3600\r\n"
        else:
            if len(sys.argv) == 4:
                if METHOD == "INVITE":
                    SIP_LINE = METHOD + " sip:" + OPTION + " SIP/2.0\r\n\r\n"\
                               + "Content-Type: application/sdp\r\n\r\n" +\
                               "v=0\r\n" + "o=" + config[0] + " " + config[2]\
                               + "\r\n" + "s=PracticaFinal\r\n" + "t=0\r\n" +\
                               "m=audio " + config[4] + " RTP\r\n"
                else:
                    SIP_LINE = METHOD + " sip:" + OPTION + " SIP/2.0\r\n\r\n"
            else:
                print("FALTA SABER EL LOGIN")
                SIP_LINE = METHOD + " SIP/2.0\r\n\r\n"

        SIP_HASH = SIP_LINE.split("\r\n")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((config[5], int(config[6])))
            print(SIP_LINE)     # Content to send.

            my_socket.send(bytes(SIP_LINE, 'utf-8'))
            log_file.write(str(actual_time()) + " Sent to " + config[5] +
                           ":" + config[6] + ": " + SIP_HASH[0] + " " + 
                           SIP_HASH[2] + "\n")
            data = my_socket.recv(1024)
            print('-- RECIEVED SIP RESPONSES --\n' + data.decode('utf-8'))
            data_hash = data.decode('utf-8').split(" ")
            log_file.write(str(actual_time()) + " Recieved from " + config[5] + 
                           ":" + config[6] + ": " + data_hash[0] + "\n")
            if "401" in data_hash:
                response = random.randint(000000000000000000000,
                                          999999999999999999999)
                SIP_LINE += "Authorization: Digest response=" + str(response)\
                            + "\r\n"
                my_socket.send(bytes(SIP_LINE, 'utf-8'))
            elif data.decode('utf-8').split(" ")[-1] == "OK\r\n\r\n" and \
               METHOD != "BYE":
                SIP_ACK = "ACK" + " sip:" + OPTION + " SIP/2.0\r\n\r\n"
                my_socket.send(bytes(SIP_ACK, 'utf-8'))
                data = my_socket.recv(1024)
                print(data.decode('utf-8'))
            my_socket.close()
            print("END OF SOCKET")
            log_file.write(str(actual_time()) + " Finishing.\n")
            log_file.close()
    except ConnectionRefusedError:
        log_file.write(str(actual_time()) + " Error: No server listening at " +
                       config[5] + " port " + config[6] + "\n")
        log_file.close()
        print("Connection Refused: Server not found.")
