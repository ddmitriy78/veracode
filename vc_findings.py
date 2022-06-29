from operator import eq
import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json

import vc_applist

api_base = "https://api.veracode.com/appsec/"
start_date = datetime.datetime.now() - datetime.timedelta(30)

def get_page_count(app_name, api):
    try:
        response = requests.get("https://api.veracode.com/appsec/v1/applications/?page=0&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)   

    if response.ok:
        data = response.json()
        
        for app in data["_embedded"]["applications"]:
            last_completed_scan_date = pd.to_datetime(app["last_completed_scan_date"])
            if app_name == app["profile"]["name"]:
                app_guid = app["guid"]    
            else:
                app_name == app["profile"]["name"]
                next 
    
    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=100&page=0" + "&" + api, auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
        list = {"app_name": app_name, "app_guid": app_guid, "total_elements": total_elements, "total_pages": total_pages}
    else:
        print(response.status_code)   
    return list    

def findings_api2(app_name, app_guid, api):     # api should be a list

    uri = "&".join(api)
    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=0" + "&" + str(uri), auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
        print("api call", "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=0" + "&" + str(uri))
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
    else:
        print(response.status_code)   
    
    output = []
    page_number = 0
    findings_count = 0
    # for x in range(1): # limiting number of pages to 5
    for x in range(total_pages):
        print("Page", x, "out of", total_pages)
        try:
            response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=" + str(x) + "&" + str(uri), auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
            print("api call", "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=" + str(x) + "&" + str(uri))
        except requests.RequestException as e:
            print("Whoops!")
            print(e)
            #sys.exit(1)
        if response.ok:
            data = response.json()
            total_pages = int(data["page"]["total_pages"])
            page_number += 1
            findings = data["_embedded"]["findings"]
            for finding in findings:
                findings_count += 1
                output.append({"app_name": app_name, "findings_count": findings_count, "finding": finding})
                
    else:
        print(response.status_code)   
    return output  
