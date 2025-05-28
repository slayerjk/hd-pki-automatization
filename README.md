This is a PKI automatization script for using with HD Naumen API and Windows PKI(CA) server.

**Use only for Russian version of Windows PKI server**

**DESCRIPTION**:
Check workflow

Script was written with Python 3.11

Main libs to use:
* For HD API used requests(2.31) lib; 
* work with CA playwright(1.42) lib

**WORKFLOW(functions)**:
1. get_hd_requests - (HD API)Get list of requests' UUIDs with type = "waitingLines"
2. get_request_service_call - (HD API)Getting Request's Service Call ID
3. get_request_details - (HD API)Getting Requests Details
4. get_request_csr - (HD API)Getting HD Request's File(CSR)
5. create_cert - (CA server, Playwright)Create certificate via MS CA server (**check carefully function for your logic**)
6. go to the ca url
7. CLICK "Request a certificate" LINK
8. CLICK "Submit a certificate request..." LINK
9. FILL TEXTFIELD WITH CSR BODY
10. SELECT CORRESPONDING TEMPLATE(**check this function, because your templates might differ**)
11. CLICK SUBMIT
12. EXPECT PAGE WITH NO ERROR("Certificate Issues")
13. SELECT "Base 64 encoded" RADIO
14. DOWNLOAD CERTIFICATE(cer/pem) - downloads dir in script's dir
15. take_request_responsiblity - (HD API)Take Responsibility on Request
16. attach_sert_n_set_wait_for_accept - (HD API)Attach cert file and Set "wait for approvement"
17. send user report 
18. logs rotation

**Additional workflow(mailing):**
* send report to users(list) (OPTIONAL)
* send error report if errors (OPTIONAL)
* log rotation - check logs_to_keep var(default is 30 days) in project_static

**FILES**:
* app.py - main app(functions call)
* project_static.py - various static data: vars mostly
* app_scripts/project_helper.py - various common helper functions
* app_scripts/project_mailing.py - data and functions to send email(smtp) reports
* app_scripts/app_functions.py - application regarding functions
* data_files/mailing_data.json - mailing data

**data_files/data-prod.json example**
```
{
  "hd-api-url": "https://<HD URL>",
  "hd-access-key": "<HD API KEY>",
  "pki-url": "https://<PKI SERVER URL>",
  "pki-user": "<PKI USER>",
  "pki-pass": "<PKI USER'S PASS>"
}
```
! There is 'data-BLANK.json' example file. Edit it and rename to 'data-prod.json'

**data_files/hd_pki-templates.json example**
```
{
  "HD_Field1": "PKI_Template-1",
  "HD_Field2": "PKI_Template-2",
  "HD_Field3": "PKI_Template-3"
}
```

! There is 'hd_pki-templates_BLANK.json' example file. Edit it and rename to 'hd_pki-templates.json'
