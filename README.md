# Growtopia AAP Recaptcha

Automate the process of creating guest accounts in Growtopia or solving the AAP (Account Authentication Process) using an Outlook email address with the assistance of capsolver, capmonster, or anticaptcha services.

## How to Use
1. Install the required dependencies:
   ```shell
   pip install -r requirements.txt
   ```

2. Execute the script with the following commands:
   Guest:
   ```shell
   python main.py --task="guest" --use_capsolver=True --api_key="API_KEY" --url_guest="URL_GUEST"
   ```

   AAP:
   ```shell
   python main.py --task="aap" --email="mail@outlook.com" --password="password_email" --use_capsolver=True --api_key="API_KEY"
   ```

## Flags
- `task`: Specifies the task to be performed. Options are:
  - `"guest"`: Create a guest account in Growtopia.
  - `"aap"`: Perform the AAP process using an Outlook email.

### Guest Task
- `url_guest`: Relevant for the `"guest"` task. Specify the URL for creating a guest account.

- `use_proxy_guest`: Enable proxy usage for the guest task by setting this flag to `True`.

- `data_proxy_guest`: If `use_proxy_guest` is `True`, provide proxy information in the format `ip:port:username:password`.

- `print_ip`: When set to `True`, the script prints IP address and country information.

- `file_status_guest`: Specifies the file to record the status of the guest task.

### AAP Task
- `email`: Relevant for the `"aap"` task. Specify the Outlook email address.

- `password`: For the `"aap"` task, provide the password for the Outlook email.

- `use_proxy_outlook`: Enable proxy usage for accessing Outlook email by setting this flag to `True`.

- `data_proxy_outlook`: If `use_proxy_outlook` is `True`, provide proxy information in the format `ip:port:username:password`.

- `use_proxy_aap`: Enable proxy usage for the AAP task by setting this flag to `True`.

- `data_proxy_aap`: If `use_proxy_aap` is `True`, provide proxy information in the format `ip:port:username:password`.

- `file_status_aap`: Specifies the file to record the status of the AAP task.

### CAPTCHA Solving Services
- `use_anticaptcha`, `use_capmonster`, `use_capsolver`: Flags to enable/disable specific CAPTCHA-solving services. Set to `True` to use the corresponding service.

- `api_key`: Required when using CAPTCHA-solving services. Provide the API key for the selected service.

## Example
![AAP](/src/img.png)

## Contact
For issues, assistance, or questions, you can contact the author on Discord at iqlasss (456374610305220611).
