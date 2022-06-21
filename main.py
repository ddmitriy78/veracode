from __future__ import annotations
import sys
from xml.etree.ElementPath import find
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json
import os

import vc_applist
import vc_findings
import vc_summaryreport

# Examples of findings API
# scan_type=SCA&cvss_gte=6" 

violates_policy_api = "violates_policy=TRUE"
annotations_api = "include_annot=TRUE"

def application_compliance():
    output = []
    app_list = vc_applist.app_list() # Get list of applications from Veracode
    for app in vc_applist.compliance(app_list):
        # print(json.dumps(app, indent=4))
        output.append(app)
    return output

def write_json_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".json")
    file1 = open("output/" + filename + ".json", 'w')
    file1.write(str(json.dumps(input, indent=4))) # write to file
    file1.close()  

    return output

if __name__ == "__main__":
    # write_json_file(application_compliance(), "vc_output_application_compliance.json")

    app_list = vc_applist.app_list() # Get list of applications from Veracode

######################################################################################
    # # Get list of findings which violate policy
    # for app in vc_applist.compliance(app_list): # This gives info including AppID to use in the findings API
    #     findings_count = 0
    #     findings = vc_findings.findings_api(app["AppID"], violates_policy_api)
    #     filename = "vc_output_" + app["AppName"] + "_" + violates_policy_api
    #     write_json_file(findings, filename)
######################################################################################
######################################################################################
    # Get all findings and save them to a file.
    # for app in vc_applist.compliance(app_list):  # This gives info including AppID to use in the findings API
    #     findigs = vc_findings.all_findings(app["AppID"])
    #     filename = "vc_output_" + app["AppName"] + "_" + "all_findings"
    #     write_json_file(findigs, filename)
######################################################################################
######################################################################################
    # # Get summary report for each application and save to file.
    # for app in vc_applist.compliance(app_list):  # This gives info including AppID to use in the findings API
    #     findigs = vc_summaryreport.report(app["AppID"])
    #     filename = "vc_output_" + app["AppName"] + "_" + "summary_report"
    #     write_json_file(findigs, filename)
######################################################################################
######################################################################################
    # # Get all findings and save them to a file.
    # for app in vc_applist.compliance(app_list):  # This gives info including AppID to use in the findings API
    #     findigs = vc_findings.sort_findings(app["AppID"], findings_api)

######################################################################################
######################################################################################
    # # Get all findings and save them to a file.
    for app in vc_applist.compliance(app_list):  # This gives info including AppID to use in the findings API
        findings = vc_findings.findings_api(app["AppID"], annotations_api)
        for finding in findings:
            print(finding)
        filename = "vc_output_" + app["AppName"] + "_" + annotations_api
        write_json_file(findings, filename)
######################################################################################


