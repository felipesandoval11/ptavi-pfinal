#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Made by Felipe Sandoval Sibada
"""Proxy Registrar that serves as a middle term in a SIP/RTP connection."""

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import socket
import time
import sys
import socketserver
import random
import json
import hashlib


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


def actual_time():
    """Format time YYYYMMDDHHMMSS for log purposes."""
    timenow = time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))
    return timenow


def sents_log(config, log_file, sip_data):
    """Sent content for log chronology purposes."""
    log_file.write(str(actual_time()) + " Sent to " + str(config[0]) +
                   ":" + str(config[1]) + ": " + sip_data + "\n")


def recieved_log(config, log_file, sip_data):
    """Recieved content for log chronology purposes."""
    log_file.write(str(actual_time()) + " Recieved from " + str(config[0]) +
                   ":" + str(config[1]) + ": " + sip_data + "\n")


def send_to_uaserver(ip, port, data):
    """Initiates a socket to send to my UA server."""
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        my_socket.connect((ip, int(port)))
        my_socket.send(bytes(data, 'utf-8'))
        log_connect = [ip, port]
        log_data = (" ").join(data.split())
        sents_log(log_connect, log_file, log_data)
        recieved = ""
        if data.split()[0] != "ACK":
            recieved = my_socket.recv(1024).decode('utf-8')
            print("-- RECIEVED REQUEST --\r\n" + recieved)
            recieved_log(log_connect, log_file, (" ").join(recieved.split()))
        my_socket.close()
    except ConnectionRefusedError:
        print("-- ALERT! -- Connection Refused in port " + port +
              ": UAServer port not found.\n")
        recieved = "SIP/2.0 504 Server Time-out\r\n\r\n"
    return recieved


def make_users(data):
    """Making my users DATABASE .txt file."""
    try:
        users_file = open(config[3])
        users_file = open(config[3], "r+")
        Found = False
        lines = users_file.readlines()
        for line in lines:
            if line.split()[0] == data.split()[0]:
                Found = True
                line.replace(line.split()[3], data.split()[3])
                line.replace(line.split()[4], data.split()[4])
                line.replace(line.split()[-1], data.split()[-1])
        if not Found:
            users_file.write(data)
    except FileNotFoundError:  # When the file does not exists.
        users_file = open(config[3], "w")
        users_file.write(data)


def find_password(user):
    """Verify password of user."""
    try:
        file = open("passwords", "r")
        lines = file.readlines()
        password = ""
        for line in lines:
            user_line = line.split()[0].split(":")[1]
            if user == user_line:
                password = line.split()[1].split(":")[1]
    except FileNotFoundError:   # When the file doesn't exists. NEED PASSWORDS.
        pasword = "00null00"
    return password


class SIPHandler(socketserver.DatagramRequestHandler):
    """Main handler of SIP responses."""
    my_dic = {}         # My active client dic.
    exist_file = True
    nonce = []          # Making a random number every time.

    def json2registered(self):
        """Method to look if there is an over-existing json file."""
        try:
            with open("active_clients.json", "r") as data_file:
                self.my_dic = json.load(data_file)
                self.exist_file = True
        except:
            self.exist_file = False

    def register2json(self):
        """Method to write a json file of my_dic."""
        with open("active_clients.json", "w") as outfile:
            json.dump(self.my_dic, outfile, indent=4, sort_keys=True,
                      separators=(',', ':'))

    def handle(self):
        """Handler to manage incoming users SIP request."""
        line = self.rfile.read()
        line_str = line.decode('utf-8').split()
        line_hash = (" ").join(line_str)
        recieved_log(self.client_address, log_file, line_hash)

        print("-- RECIEVED REQUEST --\r\n" + line.decode('utf-8'))

        if line_str[0] == "REGISTER":

            if "Digest" not in line_str:
                self.nonce.append(str(random.randint(000000000000000000000,
                                                     99999999999999999999)))
                self.wfile.write(bytes("SIP/2.0 401 Unauthorized\r\n" +
                                       "WWW Authenticate: Digest nonce=" +
                                       self.nonce[0] + "\r\n", 'utf-8'))
                s_content = "SIP/2.0 401 Unauthorized WWW Authenticate: " +\
                            "Digest nonce=" + self.nonce[0]
                sents_log(self.client_address, log_file, s_content)
            else:

                hash_recieved = line_str[-1].split("=")[1]
                user = line_str[1].split(":")[1]
                my_digest = hashlib.md5()
                my_digest.update(bytes(self.nonce[0], "utf-8"))
                my_digest.update(bytes(find_password(user), "utf-8"))
                my_digest.digest

                if hash_recieved == my_digest.hexdigest():
                    port = line_str[1].split(":")[2]
                    expire = line_str[4]
                    ip = self.client_address[1]
                    reg_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.gmtime(time.time()))
                    registered = user + " " + str(ip) + " " + port + " " +\
                                 reg_time + " " + expire + "\n"
                    make_users(registered)  # Making my database users txt.
                    time_to_del = time.strftime("%Y-%m-%d %H:%M:%S",
                                                time.gmtime(time.time() +
                                                            int(expire)))
                    self.json2registered()
                    self.my_dic[user] = {"address":
                                         str(self.client_address[0]),
                                         "port": port,
                                         "expire_time": expire,
                                         "expires": time_to_del}
                    if int(expire) == 0:
                        del self.my_dic[user]
                    self.expired()
                    self.register2json()
                else:
                    print("-- ALERT! -- User password is incorrect.\n")
                    self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
                    s_content = "SIP/2.0 400 Bad Request"
                    sents_log(self.client_address, log_file, s_content)

                self.nonce.clear()

        elif line_str[0] == "INVITE" or line_str[0] == "BYE":

            self.json2registered()
            self.expired()
            if len(line_str) != 2:
                user_to_send = line_str[1].split(":")[1]
                if self.find_register(user_to_send):
                    ip_serv = self.my_dic[user_to_send]["address"]
                    port_serv = self.my_dic[user_to_send]["port"]
                    recieved = send_to_uaserver(ip_serv, port_serv,
                                                line.decode('utf-8'))
                    self.wfile.write(bytes(recieved, "utf-8"))
                    log_hash = (" ").join(recieved.split())
                    sents_log(self.client_address, log_file, log_hash)
                else:
                    self.wfile.write(b"SIP/2.0 404 User Not Found\r\n\r\n")
                    s_content = "SIP/2.0 404 User Not Found"
                    sents_log(self.client_address, log_file, s_content)
            else:
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
                s_content = "SIP/2.0 400 Bad Request"
                sents_log(self.client_address, log_file, s_content)

        elif line_str[0] == "ACK":

            self.json2registered()
            self.expired()
            user_to_send = line_str[1].split(":")[1]
            if self.find_register(user_to_send):
                ip_serv = self.my_dic[user_to_send]["address"]
                port_serv = self.my_dic[user_to_send]["port"]
                recieved = send_to_uaserver(ip_serv, port_serv,
                                            line.decode('utf-8'))
            else:
                self.wfile.write(b"SIP/2.0 404 User Not Found\r\n\r\n")
                s_content = "SIP/2.0 404 User Not Found"
                sents_log(self.client_address, log_file, s_content)

        elif line_str[0] != "":

            self.json2registered()
            self.expired()

            if line_str[0] == "register" or line_str[0] == "invite" or\
               line_str[0] == "bye":  # Avoiding lower cases methods
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")
                s_content = "SIP/2.0 400 Bad Request"
                sents_log(self.client_address, log_file, s_content)
            else:
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")
                s_content = "SIP/2.0 405 Method Not Allowed"
                sents_log(self.client_address, log_file, s_content)

    def expired(self):
        """Method that checks if there's an old client in my_dic."""
        actual_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.gmtime(time.time()))
        expired_dic = []
        for client in self.my_dic:
            if self.my_dic[client]["expires"] < actual_time:
                expired_dic.append(client)
        for client in expired_dic:
            del self.my_dic[client]
        return self.my_dic

    def find_register(self, user):
        """Method that checks if there's a client in my active clients."""
        Found = False
        for client in self.my_dic:
            if client == user:
                return True
        return Found


def open_log(config):
    """Opening my log file previously opened by the uaclient."""
    try:
        log_file = open(config[-1])
        log_file = open(config[-1], "a")
    except FileNotFoundError:   # When the file does not exists.
        log_file = open(config[-1], "w")
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
        log_file = open_log(config)
        serv = socketserver.UDPServer((config[1], int(config[2])), SIPHandler)
        print("Server " + config[0] + " listening at port " + config[2] +
              "...\n")
        serv.serve_forever()
    except (IndexError, ValueError, FileNotFoundError):
        sys.exit("Usage: python proxy_registrar.py config")
    except KeyboardInterrupt:
        log_file.write(str(actual_time()) + " Finishing.\n")
        log_file.close
        print("END OF SERVER")
