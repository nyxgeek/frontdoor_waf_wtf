# frontdoor_waf_wtf
Script to check Azure Front Door WAF for insecure RemoteAddr variable

## Background

Azure Front Door WAF has an option to perform "IP Matching" with the RemoteAddr variable. If configured this way, the WAF is vulnerable to bypass by supplying an X-Forwarded-For header with an appropriate (approved) IP address.


## Usage

1. Connect to Azure Portal
2. Open CloudShell and upload the script
3. Run the script.

<img width="775" height="810" alt="image" src="https://github.com/user-attachments/assets/e965c262-1690-4bdb-ae92-36ab3d91d15f" />


## About

Thanks to @AdmiralGold for code contributions!

There is also a version of this available as the Check-FrontDoorWAF function in GraphRunner (https://github.com/dafthack/GraphRunner)
