import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json


api_base = "https://api.veracode.com/appsec/"
api_ver1 = "v1"
api_ver2 = "v2"
headers = {"User-Agent": "Python HMAC Example"}
start_date = datetime.datetime.now() - datetime.timedelta(30)
app_name = "Dayforce HCM Master"

def get_page_count():
 
    try: 
        response = requests.get("https://api.veracode.com/appsec/v1/applications/?page=0&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
        list = {"total_elements": total_elements, "total_pages": total_pages}
    else:
        print(response.status_code)   
    return list

def app_list():
    total_pages = get_page_count()["total_pages"]
    for page in range(total_pages):
        try: 
            response = requests.get("https://api.veracode.com/appsec/v1/applications/?page="+str(page)+"&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
        except requests.RequestException as e:
            print("Whoops!")
            print(e)
            sys.exit(1)
        if response.ok:
            data = response.json()
            return data["_embedded"]["applications"]

def scan_compliance(app_list):
    output = []
    count = 0
    for app in app_list:
        count += 1
        last_completed_scan_date = pd.to_datetime(app["last_completed_scan_date"])
        app_guid = app["guid"]
        if last_completed_scan_date is not None:
            if start_date.date() > last_completed_scan_date.date():
                scan_frequency = "Fail"
            else:
                scan_frequency = "Pass"
            list = ({"Count": str(count), "AppName": app["profile"]["name"], "LastCompleteScan": str(last_completed_scan_date.date()), "Scan_Frequency": scan_frequency, "AppID": app_guid})
            output.append(list)
    return output            


