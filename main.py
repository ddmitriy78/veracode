#from __future__ import annotations
import sys
from xml.etree.ElementPath import find
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json
import os
import csv
from copy import deepcopy

import vc_applist
import vc_findings
import vc_summaryreport

first_detection = datetime.datetime.now() - datetime.timedelta(30)


##### Examples of findings API ######
new_findings = "new=true"
sca_scan = "scan_type=SCA"
cvss_gte6 = "cvss_gte=6"
static_scan = "scan_type=STATIC"
violates_policy_api = "violates_policy=TRUE"
annotations_api = "include_annot=TRUE"
severity_gte4 = "severity_gte=4"
severity_gte3 = "severity_gte=3"
application_name = ""


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

def write_csv_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".csv")
    file1 = open("output/" + filename + ".csv", 'w')
    file1.write(str(input)) # write to file
    file1.close()  

if __name__ == "__main__":
    
    # Get list of applications from Veracode
    app_list = vc_applist.app_list() 
    # If application name exists match and replace app_list with single app record
    if application_name:
        for app in app_list:
            if application_name == app["profile"]["name"]:
                app_list = []
                app_list.append(app)
                print(app)

            break
    write_json_file(app_list, "application_list")
    
######################################################################################
    # Create custom compliance report
    compliance = vc_applist.compliance(app_list)
    data = pd.json_normalize(compliance)
    write_csv_file(data.to_csv(), "compliance")   
######################################################################################
    # Get summary report for each application and save to file.
    # for app in vc_applist.compliance(app_list):  # This gives info including AppID to use in the findings API
    #     report = vc_summaryreport.report(app["AppID"])
    #     filename = "vc_output_" + app["AppName"] + "_" + "summary_report"
    #     if report:
    #         write_json_file(report, filename)

######################################################################################
######################################################################################
    # Using findings API get findings

    for app in app_list:
        count = 1
        output = []
        app_name = (app["profile"]["name"])
        app_guid = (app["guid"])
        api = (static_scan, annotations_api, violates_policy_api)
        findings = vc_findings.findings_api2(app_name, app_guid, api)
        filename = "vc_output_" + app_name + "_" + "&".join(api)

#####################PROCESS FINDINGS######################

        for finding in findings:
            first_found_date = pd.to_datetime(finding["finding"]["finding_status"]["first_found_date"])
            last_seen_date = pd.to_datetime(finding["finding"]["finding_status"]["last_seen_date"])
            # print( first_found_date.date(), last_seen_date.date(), first_detection.date())
            finding_status = finding["finding"]["finding_status"]["status"]
            resolution = finding["finding"]["finding_status"]["resolution"]
            resolution_status = finding["finding"]["finding_status"]["resolution_status"]
            count += 1
            if finding["finding"]["finding_status"]["status"] == "OPEN" and finding["finding"]["finding_details"]["severity"] >= 3:
                if "annotations" in finding["finding"].keys():
                    print(finding)
                    output.append(finding)
                if finding["finding"]["finding_status"]["mitigation_review_status"] == "NONE" and last_seen_date.date() > first_detection.date():
                    output.append(finding)

        else:

            next

        if output:
            write_json_file(output, filename)
            data = pd.json_normalize(output)
            write_csv_file(data.to_csv(), filename) 
# ######################################################################################



