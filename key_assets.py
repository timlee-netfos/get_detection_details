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

# create application
ExtraHop_API = ExtrahopApi()

# payload of patch method to change criticality of device
payload = {
    "custom_criticality": "critical"
}

key_assets_ip = []



print("working on ---> get key assets id")
r1 = ExtraHop_API.get_info("devices")
with open(f"data/{ExtraHop_API.customer}_devices.json", "w") as fw:
    json.dump(r1.json(), fw, indent=4)
key_assets_id = [r["id"] for r in r1.json() if r["ipaddr4"] in key_assets_ip]

for id in key_assets_id:
    print("working on ---> PATCHing key assets")
    ExtraHop_API.patch_info(f"devices/{id}", payload=payload)

print(colored("DONE!", "green"))