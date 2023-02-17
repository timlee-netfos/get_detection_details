# rewrite from ExtraHop code-example
# https://github.com/ExtraHop/code-examples/tree/main/py_rx360_auth
# License: https://github.com/ExtraHop/code-examples/blob/main/LICENSE

import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib import virustotal_api
from lib.extrahop_api import ExtrahopApi
from lib.detection_details import detection_details
import ipaddress
from datetime import datetime

############## global variable start ##############
detection_type = "c2_web_beaconing"
json_directory = "c2_directions_record"
pd.set_option('display.max_rows', None)
############## global variable end   ##############

############## initial start ##############
if os.path.isdir("c2_detections_record"):
    pass 
else:
    os.mkdir("c2_detections_record")
if os.path.isdir("c2_ip_record"):
    pass 
else:
    os.mkdir("c2_ip_record")
############## initial end   ##############

# create api application
API = detection_details()

# get essential variables
API.get_token()
API.get_start_time()
API.get_end_time()

# use GET method to get c2-web-beaconing detections data from extrahop cloud
API.detection_details(detection_type)


# filter out private ip, then check if other ip malicious and make a report
with open(f"{json_directory}/{API.start_time}~{API.end_time}.json", "r") as fr:
    c2_detections = json.load(fr)

offender = []
ip_df = pd.DataFrame()

for d in c2_detections:   
    for p in d["participants"]:
        if p["role"] == "offender":
            offender.append(p["object_value"])

print("working on ---> virustotal query")
vt_dfs = []
for ip in offender:
    if ipaddress.ip_address(ip).is_private==False:
        vt_df = virustotal_api.virustotal_Ip(ip).T 
        vt_dfs.append(vt_df)
ip_df = pd.concat(vt_dfs)

# save and print the report
ip_df = ip_df.set_index('ip')
ip_df.to_csv(f"c2_ip_record/{API.start_time}~{API.end_time}.csv")
print(ip_df)


