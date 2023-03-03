import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib.virustotal_api import virustotal_api
from lib.extrahop_api import detection_details
import ipaddress
from datetime import datetime, timedelta
from termcolor import colored

############## global variable start ##############
detection_type = ["c2_web_beaconing"]
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

# create extrahop api application
ExtraHop_API = detection_details()
vt_API = virustotal_api()

# use GET method to get c2-web-beaconing detections data from extrahop cloud
c2_detections = ExtraHop_API.detection_details(detection_type, detection_directory[0])

offender = []

for d in c2_detections:
    for p in d["participants"]:
        if p["role"] == "offender":
            offender.append(p["object_value"])

print("ip amount:", len(offender))
if len(offender) > 250:
    overquota = input(colored("[WARNING] IP AMOUNT IS OVER VIRUSTOTAL QUOTA. CONTINUE? (Y/N) ", "yellow"))
    if overquota.upper() == "Y":
        pass
    elif overquota.upper() == "N":
        print(colored("Program Terminated", "red"))
        exit(1)
    else:
        print(colored("Invaled input. Program Terminated", "red"))

ip_df = vt_API.multiple_ip_check(offender)
print("done!")
print(f"private ip:" + "\n".join(vt_API.private_ip))
print(colored("\n[MALICIOUS IP]\n", "red") + "\n".join(vt_API.malicious_ip))
print(colored("[UNABLE TO ANALYZE]\n", "yellow") + "\n".join(vt_API.unable_check_ip))
ip_df.to_csv(f"{detection_directory[1]}/{ExtraHop_API.start_time}~{ExtraHop_API.end_time}.csv")
