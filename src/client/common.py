import logging
import ssl
import configparser

class Parser(configparser.ConfigParser):
    def __init__(self):
        super(configparser.ConfigParser, self).__init__(inline_comment_prefixes=("#", ";"))
    def getint(self, s, k, fallback):
        try: return configparser.ConfigParser.getint(self, s, k)
        except: return fallback
    def getfloat(self, s, k, fallback):
        try: return configparser.ConfigParser.getfloat(self, s, k)
        except: return fallback
    def getboolean(self, s, k, fallback):
        try: return configparser.ConfigParser.getboolean(self, s, k)
        except: return fallback
    
def parse(filename, required_fields={}, optional_fields={}):
    cfg = Parser()
    cfg.read(filename)

    config = {}
    for s in required_fields.keys():
        if not s in cfg: raise Exception("Unable to find {} section. Exiting".format(s))
        for k, t in required_fields[s]:
            if not k in cfg[s]: raise Exception("Unable to find {}:{}. Exiting".format(s, k))
            elif t == "int":
                config[k] = cfg.getint(s, k, fallback=None)
                if config[k] == None: raise Exception("Invalid value type for {}:{}. Expected {}".format(s, k, t))
            elif t == "float":
                config[k] = cfg.getfloat(s, k, fallback=None)
                if config[k] == None: raise Exception("Invalid value type for {}:{}. Expected {}".format(s, k, t))
            elif t == "boolean":
                config[k] = cfg.getboolean(s, k, fallback=None)
                if config[k] == None: raise Exception("Invalid value type for {}:{}. Expected {}".format(s, k, t))
            else:
                config[k] = cfg.get(s, k)

    for s in optional_fields.keys():
        for k, t, f in optional_fields[s]:
            if t == "int":
                config[k] = cfg.getint(s, k, fallback=f)
            elif t == "float":
                config[k] = cfg.getfloat(s, k, fallback=f)
            elif t == "boolean":
                config[k] = cfg.getboolean(s, k, fallback=f)
            else:
                config[k] = cfg.get(s, k, fallback=f)


    return config

def getContext(**kwargs):
    context = ssl.SSLContext(kwargs["protocol"])
    context.check_hostname = False
    context.load_verify_locations(kwargs['trustedca'])
    context.load_cert_chain(kwargs['certpath'], kwargs['keypath'])

    return context


def getLogger(**kwargs):
    if getLogger.invoked:
        return logging.getLogger("network-capture")
    getLogger.invoked = True
    
    logger = logging.getLogger('network-capture')
    formatter = logging.Formatter('%(asctime)s - %(threadName)s  - %(message)s')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    ch.setFormatter(formatter)

    if kwargs['logfile'] != None:
        fh = logging.FileHandler(kwargs['logfile'])
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

getLogger.invoked = False


