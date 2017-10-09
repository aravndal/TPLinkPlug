from modules import cbpi
from modules.core.hardware import ActorBase
from modules.core.props import Property
import urllib2, json
import uuid
import socket
import argparse
from flask import request

DEBUG = False

def log(s):
    if DEBUG:
        cbpi.app.logger.info(s)

# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171

def encrypt(string):
    key = 171
    result = "\0\0\0\0"
    for i in string:
        a = key ^ ord(i)
        key = a
        result += chr(a)
    return result

def decrypt(string):
    key = 171
    result = ""
    for i in string:
        a = key ^ ord(i)
        key = ord(i)
        result += chr(a)
    return result

def getjson(ip, data_load):
    log("Local TP Link %s / %s" % (ip, data_load))
    port = 9999
    try:
        sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_tcp.connect((ip, port))
        sock_tcp.send(encrypt(data_load))
        data = sock_tcp.recv(2048)
        sock_tcp.close()
        return decrypt(data[4:])
    except socket.error:
        log("Could not connect to host %s:%s" % (ip, port))
        cbpi.notify("TPLink Local IP Error", "Check local ip address or remove to use Cloud.", type="danger", timeout=10000)
        return False

def httpTPlink(url, data_load):
    log("Cloud TP Link %s / %s" % (url, data_load))
    try:
        data = json.loads(data_load)
        req = urllib2.Request("%s" % (url))
        req.add_header('Content-Type', 'application/json')
        resp = urllib2.urlopen(req, json.dumps(data))
        json_object = resp.read()
        response_dict = json.loads(json_object)
        return response_dict
    except Exception as e:
        cbpi.app.logger.error("FAILED when contacting TP Link site: %s" % (url))
        cbpi.notify("TPLink http Error", "Check username and password.", type="danger", timeout=10000)
        return False

def receive(data_load, ip="", url=""):
    log("Receiver %s / %s /%s" % (data_load, ip, url))
    if ip == "":
        url += "?token=%s" % tplink_token
        resp = httpTPlink(url, data_load)
        resp = resp["result"]["responseData"]
        resp = resp.replace('\"', '"')
    else:
        resp = getjson(ip, '{"system":{"get_sysinfo":null},"emeter":{"get_realtime":{}},"time":{"get_time":null}}')
    return resp

def send(command, plug="", ip=""):
    if ip == "":
        log("Send Cloud TP Link %s" % command)
        plug = plug-1
        url = TPplugs[plug]["appServerUrl"]
        url = url +"?token=%s" % tplink_token
        device = TPplugs[plug]["deviceId"]
        data_input = '{"method":"passthrough", "params": {"deviceId": "%s", "requestData": "{\\"system\\":{\\"set_relay_state\\":{\\"state\\":%s}}}" }}'
        data_input = data_input % (device, command)
        resp = httpTPlink(url, data_input)
    else:
        log("Send Local TP Link %s" % command)
        data_input = '{"system":{"set_relay_state":{"state":%s}}}' % command
        resp = getjson(ip, data_input)

def init_TPLink(MyUUID4):
    log("Get token for TPLink")
    url = "https://wap.tplinkcloud.com"
    data_input = '{ "method": "login", "params": { "appType": "Kasa_Android", "cloudUserName": "%s", "cloudPassword": "%s", "terminalUUID": "%s" } }'
    data_input = data_input % (username, password, MyUUID4)
    ## Sending http command ""
    my_response = httpTPlink(url, data_input)
    if my_response == False:
        return False
    token = my_response["result"]["token"]
    return token

def StartTPLink():
    try:
        cbpi.add_config_parameter("tplink_uuid4", "", "text", "TPLink UUID4")
        cbpi.add_config_parameter("tplink_token", "", "text", "TPLink Token")
    except:
        pass
    MyUUID4 = uuid.uuid4()
    cbpi.set_config_parameter("tplink_uuid4", str(MyUUID4))
    tplink_token = init_TPLink(MyUUID4)
    if tplink_token == False:
        return None
    cbpi.set_config_parameter("tplink_token", str(tplink_token))
    return tplink_token

def getToken():
    cbpi.app.logger.info("Get Token")
    global tplink_token
    tplink_token = cbpi.get_config_parameter("tplink_token", None)
    log("Token %s" % tplink_token)
    if (tplink_token is None or tplink_token == ""):
       if username == None:
           return False
       tplink_token = StartTPLink()

def getUser():
    cbpi.app.logger.info("Get User")
    global username, password
    username = cbpi.get_config_parameter("tplink_username", None)
    password = cbpi.get_config_parameter("tplink_password", None)
    if username is None:
        try:
            cbpi.add_config_parameter("tplink_username", "", "text", "TPLink Username")
            cbpi.add_config_parameter("tplink_password", "", "text", "TPLink Password")
        except:
            cbpi.notify("TPLink Error", "Unable to read TP Link config, update CraftBeerPi Parameter settings and reboot.", type="danger", timeout=10000)

def getPlugs():
    cbpi.app.logger.info("Get TP Plugs IDs")
    arr = []
    url = "https://wap.tplinkcloud.com?token=%s" % (tplink_token)
    data_input = '{"method":"getDeviceList"}'
    resp = httpTPlink(url, data_input)
    if resp == False:
        return []
    deviceList = resp["result"]["deviceList"]
    return deviceList

@cbpi.initalizer(order=10)
def init(cbpi):
    cbpi.app.logger.info("Initialize TPLink")
    getUser()
    if username == "":
       cbpi.notify("TPLink Error", "Unable to read TP Link config, update CraftBeerPi Parameter settings and reboot.", type="danger",     timeout=None)
       return
    getToken()
    global TPplugs
    if tplink_token != None:
        TPplugs = getPlugs()
    else:
        TPplugs = []
    cbpi.app.logger.info("Initialize TPLink - Done -")

@cbpi.actor
class TPLinkPlug(ActorBase):
    plug_name = Property.Select("Plug", [1,2,3,4,5], description="TPLink Plug")
    plug_time = Property.Number("Publish stats every minute", configurable = True, unit="s", default_value=0, description="Time in minutes to publish voltage stats, 0 is off")
    plug_ip = Property.Text("TP-Link Plug Local IP", configurable = True, default_value="192.168.0.10", description="Local IP address is used instead of Cloud service, leave blank to use cloud service.")
    c_off = 0
    d_on = 1
    cnt_timer = 0

    def on(self, power=100):
        try:
            send(command = self.d_on, plug = int(self.plug_name), ip = self.plug_ip)
        except:
            cbpi.notify("TPLinkPlug Error", "Device not correctly setup, go to Hardware settings and correct.", type="danger", timeout=10000) 

    def off(self):
        try:
            send(command = self.c_off, plug = int(self.plug_name), ip=self.plug_ip)
        except:
            cbpi.notify("TPLinkPlug Error", "Device not correctly setup, go to Hardware settings and correct.", type="danger", timeout=10000) 

    def set_power(self, power):
        pass

    def url(self):
        no = int(self.plug_name)-1
        url = TPplugs[no]["appServerUrl"]
        return url

    def device(self):
        no = int(self.plug_name)-1
        device = TPplugs[no]["deviceId"]
        return device

    def time(self):
        return self.plug_time

    def showstats(self):
        plug_time = int(self.plug_time)
        if plug_time == 0:
            return False
        self.cnt_timer += 1
        if (self.cnt_timer >= plug_time):
            self.cnt_timer = 0
            return True
        return False

    def ip(self):
        return self.plug_ip

@cbpi.backgroundtask(key="read_tplink_plug", interval=20)
def TPLinkplugs_background_task(api):

    def ddhhmmss(seconds):
        # Convert seconds to a time string "[[[DD:]HH:]MM:]SS".
        dhms = ''
        for scale in 86400, 3600, 60:
            result, seconds = divmod(seconds, scale)
            if dhms != '' or result > 0:
                dhms += '{0:02d}:'.format(result)
        dhms += '{0:02d}'.format(seconds)
        return dhms

    def NotifyStats(name, ip, url, device):
        log("TPLink Background")
        if ip == "":
            data_load = '{"method":"passthrough", "params": {"deviceId": "%s", "requestData": "{\\"system\\":{\\"get_sysinfo\\":null},\\"emeter\\":{\\"get_realtime\\":null}}"}}' % device
        else:
            data_load = '{"system":{"get_sysinfo":null},"emeter":{"get_realtime":{}},"time":{"get_time":null}}'
        resp = receive(data_load, ip, url)
        resp = json.loads(resp)
        output = ""
        if "system" in resp:
            sysinfo = resp["system"]["get_sysinfo"]
            relay_state = sysinfo["relay_state"]
            output += "Plug is "
            output += "On" if relay_state == 1 else "Off"
            timeon = sysinfo["on_time"]
            output += " for %s" % ddhhmmss(timeon)
            output += ". "
        if "emeter" in resp:
            emeter = resp["emeter"]["get_realtime"]
            output += "Voltage %.1fV, Current %.1fA Power %.0fW, Total %.2fkWh" % (emeter["voltage"], emeter["current"], emeter["power"],emeter["total"])
        if len(output) > 5:
            cbpi.notify("TPLinkPlug %s (%s)" % (name, sysinfo["alias"]), output, timeout = 90000)

    for key in cbpi.cache.get("actors"):
        value = cbpi.cache.get("actors").get(key)
        try:
            if (value.state == 1 and value.type == "TPLinkPlug"):
                if value.instance.showstats():
                    ip = value.instance.ip()
                    url = value.instance.url()
                    device = value.instance.device()
                    name = value.name
                    NotifyStats(name, ip, url, device)
        except:
            pass
