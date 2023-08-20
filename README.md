# Growtopia Recaptcha for Creating Guest Account

Enhance your guest account creation process in Growtopia with the help of [anti-captcha.com](https://anti-captcha.com/).

## How to Use
1. Install the required dependencies:
   ```shell
   pip install -r requirements.txt
   ```

2. Simply run the following command:
   ```shell
   python main.py --key="API_KEY" --url="URL_GUEST"
   ```

## Flags
- `--key`: API_KEY for anti-captcha
- `--url`: URL when creating a guest account
- `--use_proxy`: Set to True/False to use a proxy
- `--data_proxy`: Proxy data in the format: `ip:port:username:password` (supports only socks5)
- `--print_ip`: (Optional) Display your IP address
- `--file`: Write the guest status to a specified file

## Contact
For issues, help, or questions, you can reach me on Discord at iqlasss (456374610305220611).