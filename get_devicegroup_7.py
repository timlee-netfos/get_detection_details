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

r = ExtraHop_API.patch_info("devices/60129551390", payload=payload)
r1 = ExtraHop_API.get_info("devices/60129551390")
print(r1.json())
# payload["custom_criticality"] = "not_critical"
# r = ExtraHop_API.patch_info("devices/60129551390", payload=payload)
# r2 = ExtraHop_API.get_info("devices/60129551390")
# print(r2.json())

# r = ExtraHop_API.get_info("devicegroups/1")
# print(r.json())
