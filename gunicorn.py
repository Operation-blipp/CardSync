# Config for gunicorn

filepath = "settings.cfg"

def loadConfig(filepath):
    
    configData = dict()
    with open(filepath, "r") as configFile:
        
        for line in configFile.readlines():
            if line[0] == '#':
                continue
            if " = " not in line:
                continue
            lineData = line.split(" = ")
            configData[lineData[0]] = lineData[-1].strip("\n")
    
    return configData

config_dict = loadConfig(filepath)

bind = config_dict["HOST"] + ":" + config_dict["PORT"]
workers = int(config_dict["WORKERS"])