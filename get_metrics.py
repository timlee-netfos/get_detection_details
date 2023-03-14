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
    "cycle":"auto",
    "from":-604800000,
    "metric_category": "net",
    "metric_specs": [
        {
            "name": "bytes_in"
        }
    ],
    "object_type": "device_group",
    "object_ids":[
        1
    ],
    "until":0,
}

r = ExtraHop_API.post_info("metrics", payload)
with open("123.json", "w") as fw:
    json.dump(r.json(), fw)