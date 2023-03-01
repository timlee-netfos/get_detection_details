import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib import virustotal_api
from lib.extrahop_api import detection_details
import ipaddress
from datetime import datetime
from termcolor import colored

############## global variable start ##############
detection_type = ["hacking_tools"]
detection_directory = ["./detection_details/{}".format(detection_type[0]), "./ip_record/{}".format(detection_type[0])]
pd.set_option('display.max_rows', None)
############## global variable end   ##############

############## initial start ##############
for d in detection_directory:
    if os.path.isdir(d):
        pass 
    else:
        os.mkdir(d)
############## initial end   ##############

# create api application
API = detection_details()

# get essential variables
API.get_token()
API.get_start_time()
API.get_end_time()

# use GET method to get c2-web-beaconing detections data from extrahop cloud
API.detection_details(detection_type, detection_directory[0])


# filter out private ip, then check if other ip malicious and make a report
with open(f"{detection_directory[0]}/{API.start_time}~{API.end_time}.json", "r") as fr:
    hacking_tools_detections = json.load(fr)

hacking_tools = []
hacking_ip = []

for d in hacking_tools_detections:
    hacking_tools.append(d["properties"]["hacking_tool_name"])
    for participant in d["participants"]:
        if participant["role"] == "offender":
            hacking_ip.append(participant["object_value"])

hacking_dict = {
    "hacking_tools_domain": hacking_tools,
    "hacking_ip": hacking_ip
}
df = pd.DataFrame(hacking_dict).sort_values(by=["hacking_tools_domain"])
df = df.drop_duplicates()

report = f"{API.customer} {API.start_time}~{API.end_time}\n\n"
for i in set(hacking_tools):
    report += i
    suspicious_ip = "\n".join([k for k in df[df.hacking_tools_domain == i]["hacking_ip"].tolist()])
    report += f"\n{suspicious_ip}\n"
    report += "\n"

with open(f"{detection_directory[1]}/{API.start_time}~{API.end_time}.txt", "w") as fw:
    fw.write(report)

print(report)