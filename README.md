# Veracode Security Python Project

## Veracode Python HMAC Example

A simple example of usage of the Veracode Python API signing library provided in the [Veracode Documentation](https://docs.veracode.com/r/c_hmac_signing_example_python).

### Setup

Clone this repository:

    git clone https://github.com/veracode/veracode-python-hmac-example.git

Install dependencies:

    cd veracode-python-hmac-example
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

### Run

If you have saved credentials as above you can run:

    python example.py
    
Otherwise you will need to set environment variables before running `example.py`:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python example.py

# Setup VS environment for Azure Function


### Annotation API
https://docs.veracode.com/r/c_annotations_propose_mitigation_rest 

| Name 	| Type 	| Description 	|
|---	|---	|---	|
| issue_list Required 	| String 	| Comma-separated list of finding IDs. You can use the Findings API to get a list of finding IDs for an application. 	|
| comment Required 	| String 	| Enter a brief comment about the findings for issue_list. 	|
| action Required 	| String 	| Enter one of these mitigation actions:  
    - APPDESIGN states that custom business logic within the body of the application has addressed the finding. An automated process may not be able to fully identify this business logic.  
    - NETENV states that the network in which the application is running has provided an environmental control that has addressed the finding.  
    - OSENV states that the operating system on which the application is running has provided an environmental control that has addressed the finding.  
    - FP, which stands for false positive, states that Veracode has incorrectly identified a finding in your application. If you identify a finding as a potential false positive, Veracode does not exclude the potential false positive from your published report. Your organization can approve a potential false positive to exclude it from the published report. If your organization approves a finding as a false positive, your organization is accepting the risk that the finding might be valid.  
    - LIBRARY states that the current team does not maintain the library containing the finding. You referred the vulnerability to the library maintainer.  
    - ACCEPTRISK states that your business is willing to accept the risk associated with a finding. Your organization evaluated the potential risk and effort required to address the finding. 	|