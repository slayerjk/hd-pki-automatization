import json
import re
import requests
from playwright.sync_api import Playwright, expect


# GET HD REQUESTS LIST
def get_hd_requests(url: str, proxy: dict) -> list:
    """
    (HD API)Get list of requests' UUIDs with type = "waitingLines"

    :param url: hd api url(getList)
    :param proxy: proxy
    :return: iterator of UUID's

    response example: [
        {'creationdate': '2024-02-22T08:42:13+0000', 'UUID': 'data$1982034', 'title': '44_14-42-22-02-2024',
            'type': 'confirmed'},
        {'creationdate': '2024-03-05T08:09:12+0000', 'UUID': 'data$2012177', 'title': '73_14-09-05-03-2024',
            'type': 'waitingLines'}
    ]

    return example: ['data$1982092', 'data$2012177']
    """
    response = requests.get(url, proxies=proxy, verify=False)

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}')
    result = [i['UUID'] for i in filter(lambda x: x['type'] == 'waitingLines', response.json())]

    if not result:
        raise Exception('NO NEW UUIDs FOUND!')

    return result


# GET REQUEST'S SERVICE CALL
def get_request_service_call(url: str, proxy: dict, uuid: str) -> dict:
    """
    (HD API)Getting Request's Service Call ID

    :param url: url to hd api to get request details
    :param proxy: proxy
    :param uuid: request's UUID
    :return: dict, serviceCall UUID and Title

    header example:
        {"serviceCall":
            {"UUID":"serviceCall$593396173","title":"RP1706014","state":"waitLine","idHolder":""},
            "condition":"waitingLines"}

    !TESTING serviceCall$593989602, serviceCall$593989603, serviceCall$593989601

    return example: {'Title': 'RP1706014', 'UUID': 'serviceCall$593396173'}
    """
    result = dict()
    response = requests.get(url+uuid+',user', proxies=proxy, verify=False)

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}')
    header = json.loads(response.json()['fields']['header'])

    if not header:
        raise Exception(f'NO SERVICE CALL UUID FOUND! FOR {uuid}')
    result['Title'] = header['serviceCall']['title']
    result['UUID'] = header['serviceCall']['UUID']

    return result


# GET REQUEST'S DETAILS
def get_request_details(url: str, proxy: dict, uuid: str, key: str) -> dict:
    """
    (HD API)Getting Requests Details

    :param url: hd get details url
    :param proxy: proxy
    :param uuid: serviceCall UUID
    :param key: access key
    :return: dict with request details

    response exmaple:
        "sumDescription": "<font color=\"#5f5f5f\">Описание для каких систем/сервисов нужен сертификат:: <b>ыфывыф</b>
        </font><br><font color=\"#5f5f5f\">Выберите тип сертификата: <b>Внешний сертификат</b></font><br>
        <font color=\"#5f5f5f\">Ответственный ФИО: <b>А*** И***</b></font><br><font color=\"#5f5f5f\">
        Замещающий ФИО: <b>Г*** М*** И***</b></font><br><font color=\"#5f5f5f\">DNS имя: <b>
        123123ыфвфывавы</b></font><br><font color=\"#5f5f5f\">
        CSR запрос (вложить при наличии): <b>new-pki.***.csr</b></font><br>
        <font color=\"#5f5f5f\">Укажите в каких форматах необходимо выпустить сертификат::
        <b>Key +*.cer/*crt</b></font><br>",

    retrun example:
        {'Title': 'RP1706597',
        'ServiceCall': 'serviceCall$593989602',
        'Cert Type': 'Внутренний сертификат',
        'Cert Format': '*.cer/*.crt', # OR may be '*.pem'
        'Template': 'SSL',
        'Domain': 'c***.***',
        'CSR file': 'new-pki.***.csr',
        'CSR FileID': 'file$593805516',}
    """
    result = dict()

    response = requests.get(f'{url}/{uuid}?accessKey={key}', proxies=proxy, verify=False)

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}')

    if len(response.json()) == 1:
        raise Exception(f'NO DATA FOR {uuid}')

    details = json.loads(response.text)
    request_summary = details['sumDescription']
    result['Title'] = details['title']
    result['ServiceCall'] = details['UUID']

    try:
        request_cert_type = re.search(r'Выберите тип сертификата: <b>(.*?)</b>', request_summary).group(1)
    except Exception as e:
        raise Exception(f'{result["Title"]} CERT TYPE NOT FOUND\n{e}\n')
    else:
        if request_cert_type == 'Внешний сертификат':
            raise Exception(f'{result["Title"]} is for EXTERNAL CERT')
        elif request_cert_type == 'Внутренний сертификат':
            result['Cert Type'] = request_cert_type
        else:
            raise Exception(f'{result["Title"]} UNKNOWN CERT TYPE({request_cert_type})')

    try:
        request_cert_format = re.search(
            r'Укажите в каких форматах необходимо выпустить сертификат.*?<b>(.*?)</b>',
            request_summary).group(1)
    except Exception as e:
        raise Exception(f'{result["Title"]} CERT FORMAT NOT FOUND\n{e}\n')
    else:
        result['Cert Format'] = request_cert_format

    try:
        request_cert_template = re.search(r'Шаблон сертификата.*?: <b>(.*?)</b>', request_summary).group(1)
    except Exception as e:
        raise Exception(f'{result["Title"]} CERT TEMPLATE NOT FOUND\n{e}\n')
    else:
        result['Template'] = request_cert_template
        if result['Template'] == 'Другое':
            raise Exception(f'DO NOT KNOW HOW TO PRCESS THIS TEMPLATE: ({result["Template"]})')
        elif result['Template'] not in (
                'SSL',
                'Ldaps for pam',
                'Web client and server'
        ):
            raise Exception(f'TEMPLATE UNKNOWN, CHECK TEMPLATE TYPE({result["Template"]})')

    try:
        request_domain = re.search(r'Выберите домен .*?: <b>(.*?)</b>', request_summary).group(1)
    except Exception as e:
        raise Exception(f'{result["Title"]} - NO DOMAIN SELECTED\n{e}\n')
    else:
        if request_domain == 'ATMBANK.KZ' or request_domain == 'SWTBANK.KZ':
            raise Exception(f'{result["Title"]} - CERTS CREATION FOR ATMBANK/SWTBANK DOMAIN NOT AVAILABLE NOW')
        else:
            result['Domain'] = request_domain

    try:
        request_csr = re.search(r'CSR запрос .*?: <b>(.*?)</b>', request_summary).group(1)
    except Exception as e:
        raise Exception(f'{result["Title"]} NO CSR FOUND\n{e}\n')
    else:
        result['CSR file'] = request_csr
        if details['ContentFiles'][0]['UUID']:
            result['CSR FileID'] = details['ContentFiles'][0]['UUID']
        else:
            raise Exception(f'{result["Title"]} NO CSR FILE ID FOUND')

    return result


# GET REQUEST'S CSR
def get_request_csr(url: str, proxy: dict, fileid: str, key: str) -> str:
    """
    (HD API)Getting HD Request's File(CSR)

    :param url: hd get csr url
    :param proxy: proxy
    :param fileid: CSR file id
    :param key: access key
    :return: str

    return example:
        "-----BEGIN CERTIFICATE REQUEST-----
    MIIDNzCCAh8CAQAwgacxCzAJBgNVBAYTAktaMQwwCgYDVQQIDANBTEExDzANBgNV
    ...
    APiGK32ZbBPP7Ju1wthKm1+a+0jYKOu1x9S35jA5IuUc7vu/luZmQY0M+QneNOtK
    XrXpua5NLPmx88M=
    -----END CERTIFICATE REQUEST-----"
    """
    response = requests.get(f'{url}/{fileid}?accessKey={key}', proxies=proxy, verify=False)

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}')

    result = str(response.text)

    if not result:
        raise Exception(f'{fileid} NO CSR FILE ID FOUND')

    return result


# CREATING CERT FILE
def create_cert(templates: dict, url: str, user: str, password: str, req: dict, downloads: str, playwright: Playwright) -> str:
    """
    (CA server, Playwright)Create certificate via MS CA server

    :param templates: dict of corresponding keys(HD values) and values(PKI templates)
    :param url: url of PKI server
    :param user: username to auth on PKI server
    :param password: password to auth on PKI server
    :param req: dict with request's details, including CSR itself
    :param downloads: str, downloads dir for certs
    :param playwright: Playwright object
    :return: str, cert's download path(relative)

    req example:
        {'Title': 'RP1706597',
        'ServiceCall': 'serviceCall$593989602',
         'Cert Type': 'Внутренний сертификат',
         'Cert Format': '*.cer/*.crt', # OR may be '*.pem'
         'Template': 'SSL',
         'Domain': 'c***.***',
         'CSR file': 'new-pki.***.csr',
         'CSR FileID': 'file$593805516',
         'CSR Body': '-----BEGIN CERTIFICATE REQUEST-----\nMIIDNzC....5NLPmx88M=\n-----END CERTIFICATE REQUEST-----\n'}

    return example: f'{downloads}/{cert_name}.{cert_format}'
    """
    context = playwright.chromium.launch_persistent_context(
        "",
        # headless=False,
        headless=True,
        # slow_mo=1000,
        http_credentials={
            "username": user,
            "password": password
        },
        ignore_https_errors=True,
        # default timeout is 30000ms(30s)
        timeout=40000
    )

    page = context.new_page()
    page.goto(url)

    # CLICK "Request a certificate" LINK
    page.get_by_role('link', name='Request a certificate').click()

    # CLICK "Submit a certificate request..." LINK
    page.get_by_role('link', name='Submit a certificate request by using a base-64-encoded CMC or PKCS #10 file, '
                                  'or submit a renewal request by using a base-64-encoded PKCS #7	file.').click()

    # FILL TEXTFIELD WITH CSR BODY
    page.locator('#locTaRequest').fill(req['CSR Body'])

    # SELECT CORRESPONDING PKI TEMPLATE BASED ON HD RESPONSE
    try:
        template = templates[req['Template']]
    except KeyError:
        raise Exception(f'TEMPLATE NOT IN LIST, CHECK TEMPLATE TYPE({req["Template"]})')
    else:
        page.locator('#lbCertTemplateID').select_option(label=template)

    # CLICK SUBMIT
    page.locator('#btnSubmit').click()

    # EXPECT PAGE WITH NO ERROR("Certificate Issues")
    expect(page.locator('#locPageTitle')).to_have_text(re.compile('Certificate Issued'))

    # SELECT "Base 64 encoded" RADIO
    page.locator('#rbB64Enc').check()

    # DOWNLOAD CERTIFICATE(cer/pem)
    cert_name = req['CSR file']
    if len(cert_name) == 0:
        cert_name = 'result'

    if '.cer' in req['Cert Format']:
        cert_format = 'cer'
    elif '.pem' in req['Cert Format']:
        cert_format = 'pem'
    else:
        raise Exception(F'CHECK CERT FORMAT FIELD({req["Cert Format"]}), NOT CER/PEM\n')

    with page.expect_download() as download_info:
        page.locator('#locDownloadCert3').click()
    download = download_info.value
    download_path = f'{downloads}/{cert_name}.{cert_format}'
    try:
        download.save_as(download_path)
    except Exception as e:
        raise Exception(f'FAILED TO DOWNLOAD CERT WITH ERROR\n{e}\n')
    finally:
        # CLOSE PAGE(SESSION)
        page.close()
        # context.close()

    # sleep(1000)

    return download_path


# TAKE RESPONSIBLITY ON REQUEST(MAY BE NOT NECESSARY)
def take_request_responsiblity(url: str, proxy: dict, uuid: str, key: str) -> None:
    """
    (HD API)Take Responsibility on Request
    :param url: str, hd url
    :param proxy: dict, proxy
    :param uuid: str, requests title(RP*)
    :param key: str, access key
    :return: None
    """
    response = requests.get(
        f'{url}?accessKey={key}&params=\'{uuid}\',user',
        proxies=proxy,
        verify=False
    )

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}\n{response.text}')

    return None


# ATTACH FILE TO REQUEST
def attach_file_to_request(url: str, proxy: dict, file: str, uuid: str, key: str) -> None:
    """
    !DEPRECATED, USE attach_sert_n_set_wait_for_accept!

    (HD API)Attaching cert to HD Request

    :param url: str, hd get csr url
    :param proxy: dict, proxy
    :param file: str, file path
    :param uuid: str, service call uuid
    :param key: str, access key
    :return: None

    """
    response = requests.post(
        f'{url}?accessKey={key}&params=\'{uuid}\',request,user',
        proxies=proxy,
        files={"form-data": open(file, 'rb')},
        verify=False
    )

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}\n{response.text}')

    return None


# SET WAIT FOR ACCEPT
def attach_sert_n_set_wait_for_accept(
        url: str,
        proxy: dict,
        cert_path: str,
        servicecall: str,
        rp: str,
        key: str
) -> None:
    """
    (HD API)Attach cert file and Set "wait for approvement"

    :param url: str, hd url
    :param proxy: dict, proxy
    :param cert_path: str, path of cert file
    :param servicecall: str, requests serviceCall
    :param rp: str, request's title(RP*)
    :param key: str, access key
    :return: str
    """
    payload = {
        'form-data': open(cert_path, 'rb'),
        'procCodeClose': (None, 'catalogs$549821603'),
        'solution': (None, f'Запрос {rp} исполнен, сертификат во вложении.\nНа подтверждении в дирекции мониторинга.')
    }

    response = requests.post(
        f'{url}?accessKey={key}&params=\'{servicecall}\',request,user',
        proxies=proxy,
        files=payload,
        verify=False
    )

    # DEBUG RESPONSE
    # print(response.url,
    #       response.text,
    #       response.headers,
    #       response.status_code,
    #       sep='\n')

    # DEBUG REQUEST
    # print(response.request.headers, response.request.body, sep='\n')

    if response.status_code not in [200, 201, 202]:
        raise Exception(f'CHECK STATUS CODE:{response.status_code}\n{response.text}')

    return None
