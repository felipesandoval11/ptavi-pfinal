#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""UA SIP Client Program that sends RTP Audio."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import socket
import sys
import random
import os
import hashlib


try:
    CONFIG = sys.argv[1]
    METHOD = sys.argv[2]
    if len(sys.argv) == 4:
        if METHOD == "REGISTER" and not str.isdigit(sys.argv[3]):
            raise ValueError
        else:
            OPTION = sys.argv[3]
    elif len(sys.argv) != 3:
        raise IndexError
    if METHOD == "ACK":                     # Por seguridad. Avoid Spoofing.
        raise ValueError
except (IndexError, ValueError):
    sys.exit("Usage: python uaclient.py config method option")


class ConfigHandler(ContentHandler):
    """For handling configuration entries in XML format type."""

    def __init__(self):
        """Making a list with my configuration."""
        self.myconfig = []

    def startElement(self, name, attr):
        """Method to get data from my ATTLISTS."""
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
        """My configurations setting list."""
        return self.myconfig


def actual_time():
    """Format time YYYYMMDDHHMMSS for log purposes."""
    timenow = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
    return timenow


def sents_log(config, log_file, sip_data):
    """Sent content for log chronology purposes."""
    log_file.write(str(actual_time()) + " Sent to " + config[5] +
                   ":" + config[6] + ": " + sip_data + "\n")


def recieved_log(config, log_file, sip_data):
    """Recieved content for log chronology purposes."""
    log_file.write(str(actual_time()) + " Recieved from " + config[5] +
                   ":" + config[6] + ": " + sip_data + "\n")


if __name__ == "__main__":
    try:
        parser = make_parser()
        cHandler = ConfigHandler()
        parser.setContentHandler(cHandler)
        parser.parse(open(CONFIG))
        config = cHandler.get_config()
        if not os.path.exists(config[-1]):  # Does this audio file exists?.
            raise OSError
        try:
            log_file = open(config[7])
            log_file = open(config[7], "a")
        except FileNotFoundError:           # When the file does not exists.
            log_file = open(config[7], "w")
            log_file.write(str(actual_time()) + " Starting...\n")

        if METHOD == "REGISTER" or METHOD == "register":
            SIP_LINE = METHOD + " sip:" + config[0] + ":" + config[3] +\
                       " SIP/2.0\r\n\r\n" + "Expires: "
            if len(sys.argv) == 4:
                SIP_LINE += OPTION + "\r\n"
            else:
                SIP_LINE += "3600\r\n"      # Default expiration time.
        else:
            if len(sys.argv) == 4:
                SIP_LINE = METHOD + " sip:" + OPTION + " SIP/2.0\r\n"
                if METHOD == "INVITE" or METHOD == "invite":
                    SIP_LINE += "Content-Type: application/sdp\r\n\r\n" +\
                                "v=0\r\n" + "o=" + config[0] + " " + config[2]\
                                + "\r\n" + "s=PracticaFinal\r\n" + "t=0\r\n" +\
                                "m=audio " + config[4] + " RTP\r\n"
                else:
                    SIP_LINE += "\r\n"  # Adding new line in SIP.
            else:
                print("-- IMPORTANT: you did't specify the login --\n")
                SIP_LINE = METHOD + " SIP/2.0\r\n\r\n"

        SIP_HASH = (" ").join(SIP_LINE.split())     # Content to write in log.

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((config[5], int(config[6])))
            print(SIP_LINE)                 # Content to send.
            my_socket.send(bytes(SIP_LINE, 'utf-8'))
            sents_log(config, log_file, SIP_HASH)
            data = my_socket.recv(1024)

            print('-- RECIEVED SIP RESPONSES --\n' + data.decode('utf-8'))
            data_hash = data.decode('utf-8').split()
            log_data = (" ").join(data_hash)        # Content to write in log.
            recieved_log(config, log_file, log_data)
            if "401" in data_hash:

                nonce_recieved = data_hash[6].split("=")[1]
                digest = hashlib.md5()
                digest.update(bytes(nonce_recieved, "utf-8"))
                digest.update(bytes(config[1], "utf-8"))
                digest.digest
                response = random.randint(000000000000000000000,
                                          999999999999999999999)
                SIP_LINE += "Authorization: Digest response=" +\
                            digest.hexdigest() + "\r\n"
                SIP_HASH = (" ").join(SIP_LINE.split())
                sents_log(config, log_file, SIP_HASH)
                my_socket.send(bytes(SIP_LINE, 'utf-8'))
                print("-- SENDING REGISTER AGAIN --\n" + SIP_LINE)

            elif "OK" in data_hash and METHOD != "BYE":

                SIP_ACK = "ACK" + " sip:" + INVITE +\
                          " SIP/2.0\r\n\r\n"
                # CORREGIR EL SIP DE ARRIBA. ES AL QUE SE LO ENVIO.
                my_socket.send(bytes(SIP_ACK, 'utf-8'))

            elif METHOD == "BYE":

                log_file.write(str(actual_time()) + " Finishing.\n")

            my_socket.close()
            log_file.close()
            print("-- END OF SOCKET --")

    except ConnectionRefusedError:
        log_file.write(str(actual_time()) + " Error: No server listening at " +
                       config[5] + " port " + config[6] + "\n")
        log_file.close()
        print("Connection Refused: Server not found.")
    except (FileNotFoundError, OSError):
        sys.exit("Usage: python uaclient.py config method option.")
