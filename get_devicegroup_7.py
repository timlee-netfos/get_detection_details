import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib.virustotal_api import virustotal_api
from lib.extrahop_api import ExtrahopApi
import ipaddress
from datetime import datetime, timedelta
from termcolor import colored
import csv
import matplotlib.pyplot as plt

if os.path.isdir("data"):
    pass
else:
    os.mkdir("data")

# create application
ExtraHop_API = ExtrahopApi()

# get devicegroup: New Devices (Last 7 Days)
params = {
    "limit":1000
}

r1 = ExtraHop_API.get_info("devicegroups/1/devices", params=params)
# with open("data/new_devices_last_7_days.json", "w") as fw:
#     json.dump(r1.json(), fw)
device_details = r1.json()

devices = {}
devices["display_name"] = [i["display_name"] for i in device_details]
devices["MAC_Address"] = [i["macaddr"] for i in device_details]
devices["IP_Address"] = [i["ipaddr4"] for i in device_details]
devices["Discovery_Time"] = [datetime.fromtimestamp(i["discover_time"]/1000) for i in device_details]
devices["Analysis_Level"] = [i["analysis"] for i in device_details]

ids = [i["id"] for i in device_details]
Mbytes_in = []
Mbytes_out = []
for ord, id in enumerate(ids):
    if (ord+1)%10 == 1:
        print("working on ---> {}/{}".format(ord+1, len(ids)))
    payload = {
        "cycle":"auto",
        "from":-604800000,
        "metric_category": "net",
        "metric_specs": [
            {
                "name": "bytes_in"
            }
        ],
        "object_type": "device",
        "object_ids":[id],
        "until":0
    }

    r2 = ExtraHop_API.post_info("metrics/total", payload)
    try:
        Mbytes_in.append(r2.json()["stats"][0]["values"][0]/1024/1024)
    except KeyError:
        Mbytes_in.append(0)

    payload = {
        "cycle":"auto",
        "from":-604800000,
        "metric_category": "net",
        "metric_specs": [
            {
                "name": "bytes_in"
            }
        ],
        "object_type": "device",
        "object_ids":[id],
        "until":0
    }

    r3 = ExtraHop_API.post_info("metrics/total", payload)
    try:
        Mbytes_out.append(r3.json()["stats"][0]["values"][0]/1024/1024)
    except KeyError:
        Mbytes_out.append(0)

devices["MegaBytes_In"] = Mbytes_in
devices["MegaBytes_Out"] = Mbytes_out

df = pd.DataFrame(devices)
df.to_csv("data/New_Devices7({}).csv".format(datetime.now().date()))
