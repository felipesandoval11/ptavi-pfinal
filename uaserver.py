#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""UA SIP Server Program that receives RTP audio."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socketserver
import sys
import os
import time


class ConfigHandler(ContentHandler):
    """For handling configuration entries in XML format type."""

    def __init__(self):
        """Making a list with my configuration."""
        self.myconfig = []

    def valid_ip(self, ip):
        """Checking if an ip is valid."""
        if len(ip.split(".")) != 4:
            return False
        else:
            for digit in ip.split("."):
                if int(digit) > 255 or int(digit) < 0:
                    return False
            return True

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
            else:
                if not self.valid_ip(ip):
                    raise ValueError
            self.myconfig.append(ip)
            puerto = attr.get('puerto', "")
            if not str.isdigit(puerto):
                raise ValueError
            self.myconfig.append(puerto)
        elif name == 'rtpaudio':
            puerto_rtp = attr.get('puerto', "")
            if not str.isdigit(puerto_rtp):
                raise ValueError
            self.myconfig.append(puerto_rtp)
        elif name == 'regproxy':
            ipproxy = attr.get('ip', "")
            self.myconfig.append(ipproxy)
            if not self.valid_ip(ipproxy):
                raise ValueError
            puerto_proxy = attr.get('puerto', "")
            if not str.isdigit(puerto_proxy):
                raise ValueError
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


class SIPHandler(socketserver.DatagramRequestHandler):
    """Main handler of an UA Server."""

    rtp_user = []         # My destination list of RTP audio.

    def handle(self):
        """Handler to manage SIP request."""
        line = self.rfile.read()
        line_str = line.decode('utf-8').split()
        line_hash = (" ").join(line_str)
        recieved_log(config, log_file, line_hash)

        if line_str[0] == "INVITE":

            self.wfile.write(b"SIP/2.0 100 Trying\r\n\r\n")
            self.wfile.write(b"SIP/2.0 180 Ringing\r\n\r\n")
            self.wfile.write(b"SIP/2.0 200 OK\r\n")
            self.wfile.write(bytes("Content-Type: application/sdp\r\n\r\n" +
                                   "v=0\r\n" + "o=" + str(config[0]) + " " +
                                   str(config[2]) + "\r\ns=PracticaFinal\r\n" +
                                   "t=0\r\nm=audio " + str(config[4]) +
                                   " RTP\r\n\r\n", 'utf-8'))
            s_content = "SIP/2.0 100 Trying SIP/2.0 180 Ringing " +\
                        "SIP/2.0 200 OK Content-Type: application/sdp v=0 " +\
                        "o=" + config[0] + " " + config[2] + " s=Practica" +\
                        "Final t=0 m=audio " + config[4] + " RTP"
            sents_log(config, log_file, s_content)

            # making my list for rtp destination EP
            self.rtp_user.append(line_str[7])
            self.rtp_user.append(line_str[11])
            self.rtp_user.append(line_str[6].split("=")[1])

        elif line_str[0] == "ACK":

            print("-- SENDING AUDIO --\n")
            send = "./mp32rtp -i " + self.rtp_user[0] + " -p " +\
                   self.rtp_user[1] + " < " + config[-1]
            os.system(send)
            log_file.write(str(actual_time()) + " Sent to " +
                           self.rtp_user[0] + ":" + self.rtp_user[1] +
                           ": AUDIO FILE " + config[-1] + "\n")
            self.rtp_user = []

        elif line_str[0] == "BYE":

            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
            s_content = "SIP/2.0 200 OK"
            sents_log(config, log_file, s_content)
            log_file.write(str(actual_time()) + " Finishing.\n")

        elif line_str[0] != "":
            # Avoiding lower cases methods.
            if line_str[0] == "invite" or line_str[0] == "bye":
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
                s_content = "SIP/2.0 400 Bad Request"
                sents_log(config, log_file, s_content)
            else:
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")
                s_content = "SIP/2.0 405 Method Not Allowed"
                sents_log(config, log_file, s_content)

        print("-- RECIEVED REQUEST --\r\n" + line.decode('utf-8'))


def open_log(config):
    """Opening my log file previously opened by the uaclient."""
    try:
        log_file = open(config[7])
        log_file = open(config[7], "a")
    except FileNotFoundError:   # When the file does not exists.
        log_file = open(config[7], "w")
        log_file.write(str(actual_time()) + " Starting...\n")
    return log_file


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
        if not os.path.exists(config[-1]):  # Does this audio file exists?.
            raise OSError
        serv = socketserver.UDPServer((config[2], int(config[3])), SIPHandler)
        log_file = open_log(config)
        print("Listening...\n")
        serv.serve_forever()
    except (IndexError, ValueError, OSError):
        sys.exit("Usage: python uaserver.py config")
    except KeyboardInterrupt:
        print("END OF SERVER")
