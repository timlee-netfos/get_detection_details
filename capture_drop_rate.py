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

# create application
ExtraHop_API = ExtrahopApi()

# all device id: 141
payload = {
    "metric_category": "capture",
    "object_type": "system",
    "metric_specs": [
        {
            "name": "if_drops"
        }
    ],
    "cycle": "auto",
    "from": -604800000,
    "until": 0,
    "object_ids": [
        2
    ]
}

r2 = ExtraHop_API.post_info("metrics", payload)
with open("data/capture_drop_metrics.json", "w") as fw:
    json.dump(r2.json(), fw)