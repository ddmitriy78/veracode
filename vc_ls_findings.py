import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json

import vc_applist

if __name__ == "__main__":
    print(vc_applist.scan_compliance())
