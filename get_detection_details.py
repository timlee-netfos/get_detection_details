import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib.virustotal_api import virustotal_api
from lib.extrahop_api import detection_details, monthly_report
import ipaddress
from datetime import datetime, timedelta
from termcolor import colored

############## global variable start ##############
all_detections = pd.read_csv("./data/detection_catalog.csv")["type"].tolist()
while True:
    detection_type = [input("detection type (if all, input all): ")]
    if detection_type[0].lower() == "all":
        detection_type = "all_type"
        break
    elif detection_type[0] in all_detections:
        break
    else:
        print(colored("Invalid input. Please try again.", "red"))
        continue
detection_directory = ["./detection_details/{}".format(detection_type[0])]
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
ExtraHop_API = detection_details()
vt_API = virustotal_api()

# get essential variables
ExtraHop_API.get_token()
ExtraHop_API.get_start_time()
ExtraHop_API.get_end_time()

# use GET method to get c2-web-beaconing detections data from extrahop cloud
if detection_type == "all_type":
    detections = ExtraHop_API.get_info("detections").json()
else:
    detections = ExtraHop_API.detection_details(detection_type, detection_directory[0])

print(len(detections))




# for d in detections:
#     for p in d["participants"]:
