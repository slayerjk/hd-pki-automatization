#!/usr/bin/env python3
import time
from tempfile import TemporaryFile
from time import perf_counter
from playwright.sync_api import sync_playwright
import re
import urllib3

# IMPORT PROJECTS PARTS
from project_static import appname, start_date_n_time, logging, logs_dir, logs_to_keep, data_files, \
    hd_access_key, hd_api_get_list_url, hd_request_get_data_url, hd_request_get_details_url, \
    hd_request_get_csr_url, pki_url, pki_user, pki_pass, script_data, proxies, downloads_dir, \
    hd_request_attach_file_url, hd_request_take_responsibility_url, hd_request_resolve_url

from app_scripts.project_helper import files_rotate, check_create_dir, func_decor, check_file

from app_scripts.app_functions import get_hd_requests, get_request_service_call, get_request_details, get_request_csr, \
    create_cert, attach_file_to_request, take_request_responsiblity, set_wait_for_accept

# MAILING IMPORTS(IF YOU NEED)
from project_static import smtp_server, smtp_port, smtp_from_addr, mail_list_admins, mail_list_users, app_log_name
from app_scripts.project_mailing import send_mail_report

# DISABLE SSL WARNINGS
urllib3.disable_warnings()

# STARTED TEMP FILE FOR USER REPORT
user_report = TemporaryFile(mode='w+t')

# SCRIPT STARTED ALERT
logging.info(f'{appname}: SCRIPT WORK STARTED')
logging.info(f'Script Starting Date&Time is: {str(start_date_n_time)}')
logging.info('----------------------------\n')


# START PERF COUNTER
start_time_counter = perf_counter()


# CHECK DATA DIR EXIST/CREATE
func_decor(f'checking {data_files} dir exists and create if not')(check_create_dir)(data_files)


# CHECKING DATA DIRS & FILES
func_decor(f'checking {script_data} file exist', 'crit')(check_file)(script_data)
func_decor(f'checking {downloads_dir} dir exist/create', 'crit')(check_create_dir)(downloads_dir)


# CHECK MAILING DATA EXIST(IF YOU NEED MAILING)
# func_decor(f'checking {mailing_data} exists', 'crit')(check_file)(mailing_data)

"""
OTHER CODE GOES HERE
"""
user_report.write(f'{appname}: {str(start_date_n_time)}\n')
user_report.write('----------------------------\n')

# # GET NEW HD REQUESTS
logging.info(f'STARTED: getting hd requests dataIDs')
try:
    hd_requests_uuid_list = get_hd_requests(hd_api_get_list_url, proxies)
except Exception as e:
    logging.error(f'FAILED: getting hd requests dataIDs\n{e}\n, exiting')

    user_report.write('Не найдено данных для дальнейшей обработки,\nвыход из программы')
    user_report.seek(0)
    (func_decor('sending user report')(send_mail_report)
     (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))

    files_rotate(logs_dir, logs_to_keep)
    # (func_decor('sending Script Final LOG')(send_mail_report)
    #  (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='f'))
    exit()
else:
    logging.info(f'DONE: getting hd requests dataIDs')

# TEST DATA
# hd_requests_uuid_list = ['data$1982092', 'data$2012177']

logging.info(f'New Requests list is: {hd_requests_uuid_list}\n')

user_report.write(f'Всего новых заявок: {len(hd_requests_uuid_list)}\n')
user_report.write('\n')


# GET SERVICE CALL IDS
logging.info('STARTED: getting service calls ids\n')
service_calls_uids = []

for uuid in hd_requests_uuid_list:
    logging.info(f'TRYING: getting service call for {uuid}')
    try:
        uuid_result = get_request_service_call(hd_request_get_data_url, proxies, uuid)
    except Exception as e:
        logging.warning(f'FAILED: getting service call for {uuid}, \n{e}, \nskipping\n')
    else:
        service_calls_uids.append(uuid_result)
        logging.info(f'DONE: getting service call for {uuid}\n')
logging.info('DONE: getting service calls ids\n')

logging.info(f'GOT {len(service_calls_uids)}/{len(hd_requests_uuid_list)}\n')

# TEST DATA
# service_calls_uids = [
#     {'Title': 'RP1', 'UUID': 'serviceCall$593989602'},
#     {'Title': 'RP2', 'UUID': 'serviceCall$593989603'},
#     {'Title': 'RP3', 'UUID': 'serviceCall$593989601'}
# ]

if len(service_calls_uids) > 0:
    logging.info(f'FINAL LIST of SERVICE CALLS is:')

    for call in service_calls_uids:
        logging.info(call)

    user_report.write('Список новых заявок:\n')
    [print(i, file=user_report) for i in service_calls_uids]
    user_report.write('\n')
else:
    logging.error(f'NO SERVICE CALLS TO PROCESS FURTHER, exiting')
    user_report.write('Не найдено данных для дальнейшей обработки,\nвыход из программы')
    user_report.seek(0)
    (func_decor('sending user report')(send_mail_report)
        (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))

    (func_decor('sending Script Final LOG')(send_mail_report)
        (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='e'))
    files_rotate(logs_dir, logs_to_keep)
    exit()

# GET REQUEST DETAILS BY SERVICE CALL
logging.info('\nSTARTED: getting request details\n')
requests_details = []

for req in service_calls_uids:
    logging.info(f'TRYING: getting request details for {req["UUID"]}')
    try:
        service_call = get_request_details(hd_request_get_details_url, proxies, req['UUID'], hd_access_key)
    except Exception as e:
        logging.warning(f'FAILED: getting request details for {req["UUID"]}, \n{e}, \nskipping\n')
    else:
        requests_details.append(service_call)
        logging.info(f'DONE: getting request details for {req["UUID"]}\n')
logging.info('DONE: getting request details\n')

logging.info(f'REQUEST DETAILS GOT: {len(requests_details)}/{len(service_calls_uids)}')

if len(requests_details) > 0:
    logging.info(f'FINAL LIST of REQUEST DETAILS is:')

    for req in requests_details:
        logging.info(req)

    user_report.write(f'Найдено запросов для обработки: {len(requests_details)}\n\n')
    user_report.write('Детали найденных запросов:\n---\n')
    for req in requests_details:
        for i in req:
            print(f'{i}: {req[i]}', file=user_report)
        print('---', file=user_report)
    user_report.write('\n')
else:
    logging.error(f'NO DETAILS TO PROCESS FURTHER, exiting')
    user_report.write('Не найдено данных для дальнейшей обработки,\nвыход из программы')
    user_report.seek(0)
    (func_decor('sending user report')(send_mail_report)
     (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))

    # (func_decor('sending Script Final LOG')(send_mail_report)
    #     (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='e'))
    files_rotate(logs_dir, logs_to_keep)
    exit()


# GET CSR CONTENT
logging.info('\nSTARTED: getting requests CSRs\n')
requests_details_w_csr = []

for req in requests_details:
    logging.info(f'TRYING: getting request\'s CSR({req["CSR FileID"]}) for {req["Title"]}')
    try:
        csr = get_request_csr(hd_request_get_csr_url, proxies, req['CSR FileID'], hd_access_key)
    except Exception as e:
        logging.warning(f'FAILED: getting request\'s CSR({req["CSR FileID"]}) for {req["Title"]}, \n{e}, \nskipping\n')
    else:
        req['CSR Body'] = csr
        requests_details_w_csr.append(req)
        logging.info(f'DONE: getting request\'s CSR({req["CSR FileID"]}) for {req["Title"]}\n')
logging.info('DONE: getting requests CSRs\n')

logging.info(f'REQUESTS\' CSRs GOT: {len(requests_details_w_csr)}/{len(requests_details)}')

if len(requests_details_w_csr) > 0:
    logging.info(f'FINAL LIST of REQUESTS\'s CSRs is:')

    for req in requests_details_w_csr:
        logging.info(req)

    user_report.write(f'Получено содержимое CSR: {len(requests_details_w_csr)}/{len(requests_details)}\n')
    user_report.write('\n')
else:
    logging.error(f'NO CSRS TO PROCESS FURTHER, exiting')
    user_report.write('Не найдено CSR для дальнейшей обработки,\nвыход из программы')
    user_report.seek(0)
    (func_decor('sending user report')(send_mail_report)
     (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))

    (func_decor('sending Script Final LOG')(send_mail_report)
        (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='e'))
    files_rotate(logs_dir, logs_to_keep)
    exit()

# THIS IS TEST DATA
# requests_details_w_csr = [
#     {'Title': 'RP1706597',
#      'ServiceCall': 'serviceCall$593989602',
#      'Cert Type': 'Внутренний сертификат',
#      'Cert Format': '*.cer/*.crt',
#      'Template': 'SSL',
#      'Domain': 'c***.***',
#      'CSR file': 'new-pki.***.csr',
#      'CSR FileID': 'file$593805516',
#      'CSR Body': '-----BEGIN CERTIFICATE REQUEST-----'}
# ]

# CREATING CERTS
logging.info('STARTED: creating certs\n')
final_requests_details = []
for req in requests_details_w_csr:
    logging.info(f'STARTED: creating cert for {req["Title"]}')
    with sync_playwright() as playwright:
        try:
            cert_path = create_cert(pki_url, pki_user, pki_pass, req, downloads_dir, playwright)
        except Exception as e:
            logging.warning(f'FAILED: creating cert for {req["Title"]}, \n{e}, \nskipping\n')
        else:
            req['Cert filepath'] = cert_path
            final_requests_details.append(req)
            logging.info(f'DONE: creating cert for {req["Title"]}\n')
logging.info('DONE: creating certs\n')

logging.info(f'CERTS GOT: {len(final_requests_details)}/{len(requests_details_w_csr)}\n')

if len(final_requests_details) > 0:
    logging.info(f'FINAL LIST of CERTS is:')

    for req in final_requests_details:
        logging.info(f"{req['Title']}, {req['Cert filepath']}")

    user_report.write(f'Создано сертификатов: {len(final_requests_details)}/{len(requests_details_w_csr)}\n\n')
    user_report.write('Список созданных сертификатов:\n')
    [print(re.match(r'.*?/(.*)', i['Cert filepath']).group(1), file=user_report) for i in final_requests_details]
    user_report.write('\n')
else:
    logging.error(f'NO CERTS TO PROCESS FURTHER, exiting')
    user_report.write('Не найдено данных для дальнейшей обработки,\nвыход из программы')
    user_report.seek(0)
    (func_decor('sending user report')(send_mail_report)
     (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))

    (func_decor('sending Script Final LOG')(send_mail_report)
        (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='e'))
    files_rotate(logs_dir, logs_to_keep)
    exit()


# TEST DATA
# final_requests_details = [
#     {'Title': 'RP1706597',
#      'ServiceCall': 'serviceCall$593989602',
#      'Cert Type': 'Внутренний сертификат',
#      'Cert Format': '*.cer/*.crt',
#      'Template': 'SSL',
#      'Domain': 'c***.***',
#      'CSR file': 'new-pki.***.csr',
#      'CSR FileID': 'file$593805516',
#      'CSR Body': '-----BEGIN CERTIFICATE REQUEST-----\n',
#      'Cert filepath': 'downloads/new-pki.***.cer'}
# ]

# TAKE RESONSIBILITY ON REQUEST & ATTACH CERT FILE TO REQUEST
for req in final_requests_details:
    user_report.write(f'Обработка тикета - {req["Title"]}\n')
    logging.info(f'STARTED: taking responsibility on ticket for {req["Title"]}')
    # TAKE RESPONSIBILITY ON REQ
    try:
        take_request_responsiblity(hd_request_take_responsibility_url, proxies, req['ServiceCall'], hd_access_key)
    except Exception as e:
        logging.warning(f'FAILED: taking responsibility on ticket for {req["Title"]}\n{e}\n')
        user_report.write(f'{req["Title"]}: назначение ответственного - ОШИБКА\n')
    else:
        logging.info(f'DONE: taking responsibility on ticket for {req["Title"]}\n')
        user_report.write(f'{req["Title"]}: назначение ответственного - ОК\n')
        logging.info(f'STARTED: attaching cert to {req["Title"]}')
        # ATTACH CERT TO REQ
        time.sleep(5)
        try:
            (attach_file_to_request
             (hd_request_attach_file_url, proxies, req['Cert filepath'], req['ServiceCall'], hd_access_key))
        except Exception as e:
            logging.warning(f'FAILED: attaching cert to {req["Title"]}\n{e}\n')
            user_report.write(f'{req["Title"]}: загрузка сертификата в тикет - ОШИБКА\n')
        else:
            logging.info(f'DONE: attaching cert to {req["Title"]}\n')
            user_report.write(f'{req["Title"]}: загрузка сертификата в тикет - ОК\n')
            logging.info(f'STARTED: setting wait for acceptance status {req["Title"]}')
            # SET WAIT FOR ACCEPT
            time.sleep(5)
            try:
                (set_wait_for_accept
                 (hd_request_resolve_url, proxies, req['ServiceCall'], req['Title'], hd_access_key))
            except Exception as e:
                logging.warning(f'FAILED: setting wait for acceptance status {req["Title"]}\n{e}\n')
                user_report.write(f'{req["Title"]}: установка тикета в статус "ожидает подтверждения" - ОШИБКА\n')
            else:
                logging.info(f'DONE: setting wait for acceptance status {req["Title"]}\n')
                user_report.write(f'{req["Title"]}: установка тикета в статус "ожидает подтверждения" - ОК\n')
    finally:
        # SLEEP TO WAIT ALL ACCEPTANCE IS REFRESHED IN HD
        logging.info('STARTED: Waiting a min to make HD refreshed...')
        time.sleep(60)
        logging.info('DONE: Waiting a min to make HD refreshed...\n')

        user_report.write('---\n\n')
        user_report.write(f'PKI-Auto: работа программы завершена!\n')
        user_report.write(f'Затрачено вермени(s): {perf_counter() - start_time_counter}\n')


# SENDING FINAL USER REPORT
user_report.seek(0)
(func_decor('sending user report')(send_mail_report)
 (appname, mail_list_users, smtp_from_addr, smtp_server, smtp_port, mail_body=user_report.read()))


# POST-WORK PROCEDURES

# FINISH JOBS
logging.info('#########################')
logging.info('SUCCEEDED: Script job done!')
logging.info(f'Estimated time is: {perf_counter() - start_time_counter}')
logging.info('----------------------------\n')
files_rotate(logs_dir, logs_to_keep)

# (func_decor('sending Script Final LOG')(send_mail_report)
#     (appname, mail_list_admins, smtp_from_addr, smtp_server, smtp_port, log_file=app_log_name, report='f'))
