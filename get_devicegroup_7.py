import requests
import base64
import json
from dotenv import load_dotenv
import os
import pandas as pd
from lib.virustotal_api import virustotal_api
from lib.extrahop_api import detection_details, monthly_report, ExtrahopApi
import ipaddress
from datetime import datetime, timedelta
from termcolor import colored





ExtraHop_API = ExtrahopApi()


# r = ExtraHop_API.get_info("devicegroups/1")
# print(r.json())
