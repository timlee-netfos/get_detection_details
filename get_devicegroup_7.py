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

# get devicegroup: New Devices (Last 7 Days)
r = ExtraHop_API.get_info("devicegroups/1/devices")
print(r.json())
