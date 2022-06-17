import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json

import vc_applist
import vc_ls_findings

if __name__ == "__main__":
    app_list = vc_applist.app_list()
    print(app_list)
    for app in app_list:
        print(json.dumps(app, indent=2))
    # print(vc_applist.scan_compliance(app_list))