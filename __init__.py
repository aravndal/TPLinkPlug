from modules import cbpi
from modules.core.hardware import ActorBase
from modules.core.props import Property
import urllib2, json
import uuid
from flask import request

def httpTPlink(url, data_load):
    try:
        cbpi.app.logger.info("Open URL TPLink %s / %s" % (url,data_load))
        data = json.loads(data_load)
        req = urllib2.Request("%s" % (url))
        req.add_header('Content-Type', 'application/json')
        cbpi.app.logger.info("STEG 1")
        resp = urllib2.urlopen(req, json.dumps(data))
        cbpi.app.logger.info("STEG 2")
        json_object = resp.read()
        cbpi.app.logger.info("STEG 3")
        response_dict = json.loads(json_object)
        cbpi.app.logger.info("STEG 4")
        return response_dict
    except Exception as e:
        cbpi.app.logger.error("FAILED when contacting TP Link site: %s" % (url))
        cbpi.notify("TPLink http Error", "Check username and password.", type="danger", timeout=10000)
        return False

def send(command, plug=1):
    plug = plug-1
    url = TPplugs[plug]["appServerUrl"]
    url = url +"?token=%s" % tplink_token
    device = TPplugs[plug]["deviceId"]
    data_input = '{"method":"passthrough", "params": {"deviceId": "%s", "requestData": "{\\"system\\":{\\"set_relay_state\\":{\\"state\\":%s}}}" }}'
    data_input = data_input % (device, command)
    resp = httpTPlink(url, data_input)

def init_TPLink(MyUUID4):
    cbpi.app.logger.info("Get token for TPLink")
    url = "https://wap.tplinkcloud.com"
    data_input = '{ "method": "login", "params": { "appType": "Kasa_Android", "cloudUserName": "%s", "cloudPassword": "%s", "terminalUUID": "%s" } }'
    cbpi.app.logger.info("STEG A")
    data_input = data_input % (username, password, MyUUID4)
    cbpi.app.logger.info("url and data: %s / %s" % (url,data_input))
    ## Sending http command ""
    my_response = httpTPlink(url, data_input)
    cbpi.app.logger.info("STEG B: %s" % my_response)
    if my_response == False:
        cbpi.app.logger.info("STEG C")
        return False
    cbpi.app.logger.info("STEG D")
    token = my_response["result"]["token"]
    return token

def StartTPLink():
    cbpi.app.logger.info("Start TPLink")
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
    cbpi.app.logger.info("Token %s" % tplink_token)
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
    cbpi.app.logger.info("Starting TP Plug")
    plug_name = Property.Select("Plug", [1,2,3,4,5], description="TPLink Plug")
    plug_time = Property.Number("Publish stats every minute", configurable = True, unit="s", default_value=0, description="Time in minutes to publish voltage stats, 0 is off")
    c_off = 0
    d_on = 1
    cnt_timer = 0

    def on(self, power=100):
        try:
            send(self.d_on, int(self.plug_name))
        except:
            cbpi.notify("TPLinkPlug Error", "Device not correctly setup, go to Hardware settings and correct.", type="danger", timeout=10000) 

    def off(self):
        try:
            send(self.c_off, int(self.plug_name))
        except:
            cbpi.notify("TPLinkPlug Error", "Device not correctly setup, go to Hardware settings and correct.", type="danger", timeout=10000) 

    def set_power(self, power):
        pass

    def token(self):
        token = cbpi.get_config_parameter("tplink_token", None)
        if token is None:
            token = StartTPLink(username,password)
        return token

    def url(self):
        cbpi.app.logger.info("URL")
        no = int(self.plug_name)-1
        url = TPplugs[no]["appServerUrl"]
        cbpi.app.logger.info("URL")
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
        self.cnt_timer = self.cnt_timer + 1
        if (self.cnt_timer >= plug_time):
            self.cnt_timer = 0
            return True
        return False

@cbpi.backgroundtask(key="read_tplink_plug", interval=60)
def TPLinkplugs_background_task(api):
    cbpi.app.logger.info("TPLink Background Task")

    def showstats(url,device):
        url = url +"?token=%s" % tplink_token
        data_input = '{"method":"passthrough", "params": {"deviceId": "%s", "requestData": "{\\"system\\":{\\"get_sysinfo\\":null},\\"emeter\\":{\\"get_realtime\\":null}}" }}'
        data_input = data_input % (device)
        resp = httpTPlink(url, data_input)
        resp = resp["result"]["responseData"]
        resp = resp.replace('\"', '"')
        resp = json.loads(resp)
        emeter = resp["emeter"]["get_realtime"]
        sysinfo = resp["system"]["get_sysinfo"]
        cbpi.notify("TPLinkPlug %s" % sysinfo["alias"], "Voltage %.1fV, Current %.2fA Power %.2fW, Total %.2fW" % (emeter["voltage"], emeter["current"], emeter["power"],emeter["total"]), timeout = 90000)

    for key in cbpi.cache.get("actors"):
        value = cbpi.cache.get("actors").get(key)
        try:
            if (value.state == 1 and value.instance.token() > 0):
                cbpi.app.logger.info("Instance %s" % value.instance.token())
                if value.instance.showstats():
                    url = value.instance.url()
                    device = value.instance.device()
                    showstats(url, device)
        except:
            pass
