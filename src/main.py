# recaptcha growtopia
# discord.gg/payylater

import fire
import re
import requests
import logging  
import json
import socks
import socket
import urllib.request
from anticaptchaofficial.recaptchav2proxyless import *

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
        response = urllib.request.urlopen(url)
        if response.status == 200:
            data = response.read()
            decoded_data = data.decode("utf-8")
            return decoded_data
        else:
            return None
    except:
        return None

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

def find_token(html):
    token_pattern = r'name="token" type="hidden" value="([^"]*)"'
    match = re.search(token_pattern, html)
    if match:
        token_value = match.group(1)
        return token_value
    else:
        return None

def get_g_response(api_key, site_key, url_captcha):
    solver = recaptchaV2Proxyless()
    solver.set_verbose(1)
    solver.set_key(api_key)
    solver.set_website_url(url_captcha)
    solver.set_website_key(site_key)
    solver.set_soft_id(0)
    try:
        g_response = solver.solve_and_return_solution()
        return g_response
    except:
        return None

def write_to_file(content,file_write):
    file_path = f'{file_write}.txt'
    with open(file_path, 'w') as file:
        file.write(content)

def captcha(url="", use_proxy=False, data_proxy="", file="status_solver", key="", print_ip=False):
    if url == "":
        return "Error"
    logging.basicConfig(filename='solver_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    gt_html = get_data_html(url,use_proxy,data_proxy)
    if gt_html == None:
        logging.error('Error when request to growtopiagame, maybe your proxy error or ip got blocked')
        write_to_file('Error when request to growtopiagame, maybe your proxy error or ip got blocked', file)
        return None
    site_key = find_sitekey(gt_html)
    try:
        g_response = get_g_response(key, site_key, url)
    except:
        logging.error("Error solving captcha")
        write_to_file("Error solving captcha", file)
        print("Error solving captcha")
        return None
    c = find__token(gt_html)
    d = find_token(gt_html)
    logging.info('_token : %s', c)
    logging.info('token : %s', d)
    
    payload = {
        "_token": f"{c}",
        "g-recaptcha-response": f"{g_response}",
        "token": f"{d}"
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
        print("Country:", parsed_data["country"])
        print("Ip:", parsed_data["query"])
    response = requests.post(url="https://www.growtopiagame.com/player/validate", data=payload, headers=headers)
    if response.status_code == 200:
        # print(response.text)
        if "Guest account has been created. Please go back in the game and continue enjoy playing game" in response.text:
            logging.info('Success created Guest with token : %s', c)
            write_to_file("success", file)
            print("Success created Guest")
            return True
        elif "Token is invalid. Please go back in game and try to create guest account again." in response.text:
            logging.error('Token is invalid : %s', c)
            write_to_file("Token is invalid", file)
            print("Token is invalid")
            return False
        elif "Please validate the captcha to create a new guest account on Growtopia" in response.text:
            logging.error('Captcha wrong : %s', c)
            write_to_file("captcha wrong", file)
            print("captcha wrong")
            return False
        elif "Failed to create guest account. Please try again soon." in response.text:
            logging.error('Failed to create guest account. Please try again soon. : %s', c)
            write_to_file("Failed to create guest account. Please try again soon.", file)
            print("Failed to create guest account. Please try again soon.")
            return False
        else:
            logging.error('Error created guest with token : %s', c)
            write_to_file("Error created guest", file)
            print("Error created guest")
            return False
    else:
        logging.error('Error an occured')
        write_to_file("Error an occured", file)
        return False

if __name__ == '__main__':
  fire.Fire(captcha)