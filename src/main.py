# recaptcha growtopia
# aap growtopia

import fire
import re
import requests
import logging  
import json
import socks
import socket
import imaplib
import email
from anticaptchaofficial.recaptchav2proxyless import *
import capmonster_python 
import capsolver_api

OTP_AAP = ""
LINK_AAP = ""
GROWID = ""
DEFAULT_PROXY_CONFIG = socks.get_default_proxy()
DEFAULT_SOCKET = socket.socket
LOGGING = ""

def find_sitekey(html):
    pattern = r'data-sitekey="([^"]+)"'
    match = re.findall(pattern, html)
    if match:
        site_key = match[0]
        return site_key
    else:
        return None

def find__token(html):
    token_pattern = r'name="_token" type="hidden" value="([^"]*)"'
    match = re.search(token_pattern, html)
    if match:
        token_value = match.group(1)
        return token_value
    else:
        return None

def find_action_url(html):
    pattern = r'action="([^"]+)"'
    match = re.search(pattern, html)
    if match:
        action_value = match.group(1)
        return action_value
    else:
        return None

def find_token(html):
    token_pattern = r'name="token" type="hidden" value="([^"]*)"'
    match = re.search(token_pattern, html)
    if match:
        token_value = match.group(1)
        return token_value
    else:
        return None

def get_data_html(url, use_proxy, proxy):
    if use_proxy:
        # proxy format -> ip:port:username:password
        final_split = proxy.split(":")
        IP_ADDR = final_split[0]
        PORT = int(final_split[1])
        USERNAME = final_split[2]
        PASSWORD = final_split[3]
        socks.set_default_proxy(socks.SOCKS5, IP_ADDR, PORT, username=USERNAME, password=PASSWORD)
        socket.socket = socks.socksocket
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        }
        response = requests.get(url,headers=headers)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except:
        return None

def get_g_response(api_key, site_key, url, use_anticaptcha, use_capmonster, use_capsolver):
    if use_anticaptcha:
        solver = recaptchaV2Proxyless()
        solver.set_verbose(1)
        solver.set_key(api_key)
        solver.set_website_url(url)
        solver.set_website_key(site_key)
        solver.set_soft_id(0)
        try:
            g_response = solver.solve_and_return_solution()
            return g_response
        except:
            return None
    elif use_capmonster:
        capmonster = capmonster_python.RecaptchaV2Task(api_key)
        task_id = capmonster.create_task(url, site_key)        
        try:
            result = capmonster.join_task_result(task_id)
            return result.get("gRecaptchaResponse")
        except:
            return None
    elif use_capsolver:
        capsolver = capsolver_api.ReCaptchaV2Task(api_key)
        task_id = capsolver.create_task(task_type='ReCaptchaV2TaskProxyLess',
                                        website_url=f'{url}',
                                        website_key=f'{site_key}'
                                        )
        try:
            captcha_key = capsolver.get_solution(task_id)
            return captcha_key.get("gRecaptchaResponse")
        except:
            return None

def write_to_file(content,file_write):
    file_path = f'{file_write}.txt'
    with open(file_path, 'w') as file:
        file.write(content)

def logs(logging, content, file):
    print(content)
    logging(content)
    if file != False:
        write_to_file(content, file)

def process_emails(data, mail):
    global OTP_AAP, LINK_AAP, GROWID
    if data[0]:
        for num in data[0].split():
            _, email_data = mail.fetch(num, "(RFC822)")
            raw_email = email_data[0][1]
            email_message = email.message_from_bytes(raw_email)
            body = ""
            if email_message.is_multipart() and raw_email:
                for part in email_message.walk():
                    ctype = part.get_content_type()
                    cdispo = str(part.get('Content-Disposition'))

                    if ctype == 'text/plain' and 'attachment' not in cdispo:
                        body = part.get_payload(decode=True).decode('utf-8')
                        break
            else:
                body = email_message.get_payload(decode=True).decode('utf-8')
            snip_a = body.find("Growtopia Account Registration for")
            snip_b = body.find("</span><!--<![endif]-->")
            account_growid_before = body[snip_a+35:snip_b]
            index_before_account = account_growid_before.find("</title>")
            account_growid = account_growid_before[0:index_before_account]
            link_match = re.search(r'(https?://growtopiagame.com/player/[^\s]+)', body)
            if link_match:
                link_before = link_match.group()
                link = link_before.replace('"',"")
                otp_match = re.search(r'<strong>(\d+)</strong>', body)
                if otp_match:
                    otp = otp_match.group(1)
                    OTP_AAP = otp
                    LINK_AAP = link
                    GROWID = account_growid
        for num in data[0].split():
            mail.store(num, '+FLAGS', '\\Deleted')
        mail.expunge()
    if OTP_AAP == "" or LINK_AAP == "":
        return None
    return True

def aap(use_proxy, data_proxy, api_key, url, otp, file, use_anticaptcha, use_capmonster, use_capsolver):
    global DEFAULT_PROXY_CONFIG, DEFAULT_SOCKET, LOGGING
    if DEFAULT_PROXY_CONFIG is not None:
        socks.set_default_proxy(*DEFAULT_PROXY_CONFIG)
    socket.socket = DEFAULT_SOCKET
    try:
        gt_html = get_data_html(url, use_proxy, data_proxy)
        if gt_html == None:
            logs(LOGGING.error, "Your ip maybe got blocked by growtopia", file)
            return None
        _token = find__token(gt_html)
        site_key = find_sitekey(gt_html)
        post_url = find_action_url(gt_html)
        logs(LOGGING.info, "Start solve captcha", False)
        try:
            g_response = get_g_response(api_key, site_key, url, use_anticaptcha, use_capmonster, use_capsolver)
        except:
            logs(LOGGING.error, "an error occured on captcha", file)
            return None

        if g_response == None:
            logs(LOGGING.error, "Failed solve captcha", file)
            return None
        logs(LOGGING.info, "Success solve captcha", False)
        payload = {
            "_token": f"{_token}",
            "userOTP": f"{otp}",
            "g-recaptcha-response": f"{g_response}"
        }
        headers = {
            "Host": "www.growtopiagame.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Referer": f"{url}"
        }
        response = requests.post(url=f"{post_url}", data=payload, headers=headers)
        if response.status_code == 200:
            if "Email address successfully verified. You can log in to the game using your GrowID now" in response.text:
                write_to_file("success aap", file)
                return True
            else:
                write_to_file("failed", file)
                return False
        else:
            write_to_file("failed", file)
            return False

    except:
        write_to_file("An error occured", file)
        return None

def check_emails(email_account, password, use_proxy_outlook, proxy_access_outlook, use_proxy_gt, proxy_access_gt, api_key, use_anticaptcha, use_capmonster, use_capsolver, file):
    global DEFAULT_PROXY_CONFIG, DEFAULT_SOCKET, LINK_AAP, OTP_AAP, GROWID, LOGGING
    logging.basicConfig(filename='aap_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    LOGGING = logging
    try:
        if use_proxy_outlook:
            # proxy format -> ip:port:username:password
            final_split = proxy_access_outlook.split(":")
            IP_ADDR = final_split[0]
            PORT = int(final_split[1])
            USERNAME = final_split[2]
            PASSWORD = final_split[3]
            socks.set_default_proxy(socks.SOCKS5, IP_ADDR, PORT, username=USERNAME, password=PASSWORD)
            socket.socket = socks.socksocket
        elif not use_proxy_outlook:
            if DEFAULT_PROXY_CONFIG is not None:
                socks.set_default_proxy(*DEFAULT_PROXY_CONFIG)
            socket.socket = DEFAULT_SOCKET

        response = requests.get("http://ip-api.com/json/")
        result = json.loads(response.content)
        logs(LOGGING.info, f'IP Address: {result["query"]} Country: {result["country"]}', False)

        mail = imaplib.IMAP4_SSL('outlook.live.com')
        logs(LOGGING.info, f"login outlook email {email_account}", False)
        mail.login(email_account, password)
        logs(LOGGING.info, f"checking folders mail", False)
        folders = ["inbox", "Junk"]
        for folder in folders:
            mail.select(folder)
            result, data = mail.search(None, "UNSEEN")
            data_aap = process_emails(data, mail)
        logs(LOGGING.info, f"Logout outlook email {email_account}", False)
        mail.logout()
        if data_aap is None:
            return None
        do_aap = aap(use_proxy_gt, proxy_access_gt, api_key, LINK_AAP, OTP_AAP, file, use_anticaptcha, use_capmonster, use_capsolver)
        if do_aap == True:
            logs(LOGGING.info, f"Growid: {GROWID} with email: {email_account} succes verified", False)
            OTP_AAP = ""
            LINK_AAP = ""
            GROWID = ""
        else:
            logs(LOGGING.error, f"{email_account} Error an occured", False)
    except:
        logs(LOGGING.error, "Login failed or failed aap", False)

def guest(url, use_proxy, data_proxy, file, key, print_ip, use_anticaptcha, use_capmonster, use_capsolver):
    if url == "":
        return "Error"
    logging.basicConfig(filename='guest_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    gt_html = get_data_html(url,use_proxy,data_proxy)
    if gt_html == None:
        logs(logging.error, "Error when request to growtopiagame, maybe your proxy error or ip got blocked", file)
        return None
    site_key = find_sitekey(gt_html)
    try:
        g_response = get_g_response(key, site_key, url, use_anticaptcha, use_capmonster, use_capsolver)
    except:
        logs(logging.error, "Error solving captcha", file)
        return None
    _token = find__token(gt_html)
    token = find_token(gt_html)
    logs(logging.info, f"_token : {_token}", False)
    logs(logging.info, f"token : {token}", False)
    
    payload = {
        "_token": f"{_token}",
        "g-recaptcha-response": f"{g_response}",
        "token": f"{token}"
    }
    headers = {
        "Host": "www.growtopiagame.com",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Referer": f"{url}"
    }

    if print_ip:
        res = requests.get("http://ip-api.com/json/")
        parsed_data = json.loads(res.text)
        logs(logging.info, f'Country: {parsed_data["country"]}', False)
        logs(logging.info, f'Ip: {parsed_data["query"]}', False)
    response = requests.post(url="https://www.growtopiagame.com/player/validate", data=payload, headers=headers)
    if response.status_code == 200:
        # print(response.text)
        if "Guest account has been created. Please go back in the game and continue enjoy playing game" in response.text:
            logs(logging.info, "success created guest", file)
            return True
        elif "Token is invalid. Please go back in game and try to create guest account again." in response.text:
            logs(logging.error, "token is invalid", file)
            return False
        elif "Please validate the captcha to create a new guest account on Growtopia" in response.text:
            logs(logging.error, "Captcha wrong", file)
            return False
        elif "Failed to create guest account. Please try again soon." in response.text:
            logs(logging.error, "Failed to create guest account. Please try again soon.", file)
            return False
        else:
            logs(logging.error, f"Error created guest with token : {_token}", file)
            return False
    else:
        logs(logging.error, "Error an occured", file)
        return False

def main(
        task="",
        url_guest="",
        use_proxy_guest=False,
        data_proxy_guest="",
        print_ip=False,
        file_status_guest="status_guest",
        
        email="",
        password="",
        use_proxy_outlook=False,
        data_proxy_outlook="",
        use_proxy_aap=False,
        data_proxy_aap="",
        file_status_aap="status_aap",
        
        use_anticaptcha=False,
        use_capmonster=False,
        use_capsolver=False,
        api_key="",
    ):
    if task == "guest":
        guest(url_guest, use_proxy_guest, data_proxy_guest, file_status_guest, api_key, print_ip, use_anticaptcha, use_capmonster, use_capsolver)
    elif task == "aap":
        check_emails(email, password, use_proxy_outlook, data_proxy_outlook, use_proxy_aap, data_proxy_aap, api_key, use_anticaptcha, use_capmonster, use_capsolver, file_status_aap)
    else:
        return "task error"

if __name__ == '__main__':
  fire.Fire(main)