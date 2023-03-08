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


ExtraHop_API = ExtrahopApi()

payload = {
    "custom_criticality": "critical"
}

key_assets_ip = []

# r = ExtraHop_API.patch_info("devices/60129551390", payload=payload)
# r1 = ExtraHop_API.get_info("devices/60129551390")
# print(r1.json())
r2 = ExtraHop_API.get_info("devices")
with open(f"data/{ExtraHop_API.customer}_devices.json", "w") as fw:
    json.dump(r2.json(), fw, indent=4)
key_assets_id = [r["id"] for r in r2.json() if r["ipaddr4"] in key_assets_ip]
print(colored("DONE!", "green"))