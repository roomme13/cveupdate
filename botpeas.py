import requests
import datetime
import pathlib
import json
import os
import yaml
import vulners

from os.path import join
from enum import Enum
from discord import Webhook, RequestsWebhookAdapter


CIRCL_LU_URL = "https://cve.circl.lu/api/query"
CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

KEYWORDS_CONFIG_PATH = join(pathlib.Path(__file__).parent.absolute(), "config/botpeas.yaml")
ALL_VALID = False
DESCRIPTION_KEYWORDS_I = []
DESCRIPTION_KEYWORDS = []
PRODUCT_KEYWORDS_I = []
PRODUCT_KEYWORDS = []


class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


################## LOAD CONFIGURATIONS ####################

def load_keywords():
    ''' Load keywords from config file '''

    global ALL_VALID
    global DESCRIPTION_KEYWORDS_I, DESCRIPTION_KEYWORDS
    global PRODUCT_KEYWORDS_I, PRODUCT_KEYWORDS
    global NTFY_URL, NTFY_TOPIC, NTFY_AUTH

    with open(KEYWORDS_CONFIG_PATH, 'r') as yaml_file:
        keywords_config = yaml.safe_load(yaml_file)
        print(f"Loaded keywords: {keywords_config}")
        ALL_VALID = keywords_config["ALL_VALID"]
        DESCRIPTION_KEYWORDS_I = keywords_config["DESCRIPTION_KEYWORDS_I"]
        DESCRIPTION_KEYWORDS = keywords_config["DESCRIPTION_KEYWORDS"]
        PRODUCT_KEYWORDS_I = keywords_config["PRODUCT_KEYWORDS_I"]
        PRODUCT_KEYWORDS = keywords_config["PRODUCT_KEYWORDS"]
        #NTFY_URL = keywords_config.get("NTFY_URL", "")
        #NTFY_TOPIC = keywords_config.get("NTFY_TOPIC", "")
        #NTFY_AUTH = keywords_config.get("NTFY_AUTH", "")


def load_lasttimes():
    ''' Load lasttimes from json file '''

    global LAST_NEW_CVE, LAST_MODIFIED_CVE

    try:
        with open(CVES_JSON_PATH, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = datetime.datetime.strptime(cves_time["LAST_NEW_CVE"], TIME_FORMAT)
            LAST_MODIFIED_CVE = datetime.datetime.strptime(cves_time["LAST_MODIFIED_CVE"], TIME_FORMAT)

    except Exception as e: #If error, just keep the fault date (today - 1 day)
        print(f"ERROR, using default last times.\n{e}")
        pass

    print(f"Last new cve: {LAST_NEW_CVE}")
    print(f"Last modified cve: {LAST_MODIFIED_CVE}")


def update_lasttimes():
    ''' Save lasttimes in json file '''

    with open(CVES_JSON_PATH, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)



################## SEARCH CVES ####################

def get_cves(tt_filter:Time_Type) -> dict:
    ''' Given the headers for the API retrive CVEs from cve.circl.lu '''
    now = datetime.datetime.now() - datetime.timedelta(days=1)
    now_str = now.strftime("%d-%m-%Y")

    headers = {
        "time_modifier": "from",
        "time_start": now_str,
        "time_type": tt_filter.value,
        "limit": "100",
    }
    r = requests.get(CIRCL_LU_URL, headers=headers)

    return r.json()


def get_new_cves() -> list:
    ''' Get CVEs that are new '''

    global LAST_NEW_CVE

    cves = get_cves(Time_Type.PUBLISHED)
    filtered_cves, new_last_time = filter_cves(
            cves["results"],
            LAST_NEW_CVE,
            Time_Type.PUBLISHED
        )
    LAST_NEW_CVE = new_last_time

    return filtered_cves


def get_modified_cves() -> list:
    ''' Get CVEs that has been modified '''

    global LAST_MODIFIED_CVE

    cves = get_cves(Time_Type.LAST_MODIFIED)
    filtered_cves, new_last_time = filter_cves(
            cves["results"],
            LAST_MODIFIED_CVE,
            Time_Type.PUBLISHED
        )
    LAST_MODIFIED_CVE = new_last_time

    return filtered_cves


def filter_cves(cves: list, last_time: datetime.datetime, tt_filter: Time_Type) -> list:
    ''' Filter by time the given list of CVEs '''

    filtered_cves = []
    new_last_time = last_time

    for cve in cves:
        cve_time = datetime.datetime.strptime(cve[tt_filter.value], TIME_FORMAT)
        if cve_time > last_time:
            if ALL_VALID or is_summ_keyword_present(cve["summary"]) or \
                is_prod_keyword_present(str(cve["vulnerable_configuration"])):
                
                filtered_cves.append(cve)

        if cve_time > new_last_time:
            new_last_time = cve_time

    return filtered_cves, new_last_time


def is_summ_keyword_present(summary: str):
    ''' Given the summary check if any keyword is present '''

    return any(w in summary for w in DESCRIPTION_KEYWORDS) or \
            any(w.lower() in summary.lower() for w in DESCRIPTION_KEYWORDS_I)


def is_prod_keyword_present(products: str):
    ''' Given the summary check if any keyword is present '''
    
    return any(w in products for w in PRODUCT_KEYWORDS) or \
            any(w.lower() in products.lower() for w in PRODUCT_KEYWORDS_I)


def search_exploits(cve: str) -> list:
    ''' Given a CVE it will search for public exploits to abuse it '''
    
    return []
    #TODO: Find a better way to discover exploits

    vulners_api_key = os.getenv('VULNERS_API_KEY')
    
    if vulners_api_key:
        vulners_api = vulners.Vulners(api_key=vulners_api_key)
        cve_data = vulners_api.searchExploit(cve)
        return [v['vhref'] for v in cve_data]
    
    else:
        print("VULNERS_API_KEY wasn't configured in the secrets!")
    
    return []


#################### GENERATE MESSAGES #########################

def generate_new_cve_message(cve_data: dict) -> str:
    ''' Generate new CVE message for sending to slack '''

    message = f"🚨  *{cve_data['id']}*  🚨\n"
    message += f"🔮  *CVSS*: {cve_data['cvss']}\n"
    message += f"📅  *Published*: {cve_data['Published']}\n"
    message += "📓  *Summary*: " 
    message += cve_data["summary"] if len(cve_data["summary"]) < 500 else cve_data["summary"][:500] + "..."
    
    if cve_data["vulnerable_configuration"]:
        message += f"\n🔓  *Vulnerable* (_limit to 10_): " + ", ".join(cve_data["vulnerable_configuration"][:10])
    
    message += "\n\n🟢 ℹ️  *More information* (_limit to 5_)\n" + "\n".join(cve_data["references"][:5])
    
    message += "\n"

    #message += "\n\n(Check the bots description for more information about the bot)\n"
    
    return message


def generate_modified_cve_message(cve_data: dict) -> str:
    ''' Generate modified CVE message for sending to slack '''

    message = f"📣 *{cve_data['id']}*(_{cve_data['cvss']}_) was modified the {cve_data['last-modified'].split('T')[0]} (_originally published the {cve_data['Published'].split('T')[0]}_)\n"
    return message


def generate_public_expls_message(public_expls: list) -> str:
    ''' Given the list of public exploits, generate the message '''

    message = ""

    if public_expls:
        message = "😈  *Public Exploits* (_limit 20_)  😈\n" + "\n".join(public_expls[:20])

    return message


#################### SEND MESSAGES #########################

def send_slack_mesage(message: str, public_expls_msg: str):
    ''' Send a message to the slack group '''

    slack_url = os.getenv('SLACK_WEBHOOK')

    if not slack_url:
        print("SLACK_WEBHOOK wasn't configured in the secrets!")
        return
    
    json_params = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": message
                }
            },
            {
                "type": "divider"
            }
        ]
    }

    if public_expls_msg:
        json_params["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": public_expls_msg
                }
        })

    requests.post(slack_url, json=json_params)


def send_telegram_message(message: str, public_expls_msg: str):
    ''' Send a message to the telegram group '''

    telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')    

    if not telegram_bot_token:
        print("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        return
    
    if not telegram_chat_id:
        print("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        return
    
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    message = message.replace(".", "\\.").replace("-", "\\-").replace("(", "\\(").replace(")", "\\)").replace("_", "").replace("[","\\[").replace("]","\\]").replace("{","\\{").replace("}","\\}").replace("=","\\=")
    r = requests.get(f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?parse_mode=MarkdownV2&text={message}&chat_id={telegram_chat_id}')

    resp = r.json()
    if not resp['ok']:
        r = requests.get(f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?parse_mode=MarkdownV2&text=Error with' + message.split("\n")[0] + f'{resp["description"]}&chat_id={telegram_chat_id}')
        resp = r.json()
        if not resp['ok']:
            print("ERROR SENDING TO TELEGRAM: "+ message.split("\n")[0] + resp["description"])

            
def send_discord_message(message: str, public_expls_msg: str):
    ''' Send a message to the discord channel webhook '''

    discord_webhok_url = os.getenv('DISCORD_WEBHOOK_URL')

    if not discord_webhok_url:
        print("DISCORD_WEBHOOK_URL wasn't configured in the secrets!")
        return
    
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    message = message.replace("(", "\\(").replace(")", "\\)").replace("_", "").replace("[","\\[").replace("]","\\]").replace("{","\\{").replace("}","\\}").replace("=","\\=")
    webhook = Webhook.from_url(discord_webhok_url, adapter=RequestsWebhookAdapter())
    if public_expls_msg:
        message = message + "\n" + public_expls_msg
    
    webhook.send(message)

def send_pushover_message(message: str, public_expls_msg: str):
    ''' Send a message to the pushover device '''

    pushover_device_name = os.getenv('PUSHOVER_DEVICE_NAME')
    pushover_user_key = os.getenv('PUSHOVER_USER_KEY')
    pushover_token = os.getenv('PUSHOVER_TOKEN') 

    if not pushover_device_name:
        print("PUSHOVER_DEVICE_NAME wasn't configured in the secrets!")
        return 
    if not pushover_user_key:
        print("PUSHOVER_USER_KEY wasn't configured in the secrets!")
        return
    if not pushover_token:
        print("PUSHOVER_TOKEN wasn't configured in the secrets!")
        return
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    data = { "token": pushover_token, "user": pushover_user_key, "message": message , "device": pushover_device_name}
    try:
        r = requests.post("https://api.pushover.net/1/messages.json", data = data)
    except Exception as e:
        print("ERROR SENDING TO PUSHOVER: "+ message.split("\n")[0] +message)


def send_ntfy_message(message: str, public_expls_msg: str):
    ''' Send a message to the ntfy.sh topic '''

    ntfy_url = os.getenv('NTFY_URL')
    ntfy_topic = os.getenv('NTFY_TOPIC')
    ntfy_auth = os.getenv('NTFY_AUTH')

    if not ntfy_url:
        print("NTFY_URL wasn't configured in the environment variables!")
        return

    if not ntfy_topic:
        print("NTFY_TOPIC wasn't configured in the environment variables!")
        return

    # Combine message and public exploits message if exists
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    full_ntfy_url = f"{ntfy_url}/{ntfy_topic}"

    headers = {
        "Title": "New CVE Alert",
        "Priority": "high",
    }

    if ntfy_auth:
        headers["Authorization"] = ntfy_auth

    print(full_ntfy_url)
    response = requests.post(full_ntfy_url, data=message.encode('utf-8'), headers=headers)

    if response.status_code == 200:
        print(f"Notification sent to ntfy.sh topic: {ntfy_topic}")
    else:
        print(f"Failed to send notification to ntfy.sh. Status code: {response.status_code}, Response: {response.text}")

#################### MAIN #########################

def main():
    #Load configured keywords
    load_keywords()

    #Start loading time of last checked ones
    load_lasttimes()

    #Find a publish new CVEs
    new_cves = get_new_cves()

    new_cves_ids = [ncve['id'] for ncve in new_cves]
    print(f"New CVEs discovered: {new_cves_ids}")

    for new_cve in new_cves:
        public_exploits = search_exploits(new_cve['id'])
        cve_message = generate_new_cve_message(new_cve)
        public_expls_msg = generate_public_expls_message(public_exploits)
        send_slack_mesage(cve_message, public_expls_msg)
        send_telegram_message(cve_message, public_expls_msg)
        send_discord_message(cve_message, public_expls_msg)
        send_pushover_message(cve_message, public_expls_msg)
        send_ntfy_message(cve_message, public_expls_msg)

    #Find and publish modified CVEs
    modified_cves = get_modified_cves()

    modified_cves = [mcve for mcve in modified_cves if not mcve['id'] in new_cves_ids]
    modified_cves_ids = [mcve['id'] for mcve in modified_cves]
    print(f"Modified CVEs discovered: {modified_cves_ids}")

    for modified_cve in modified_cves:
        public_exploits = search_exploits(modified_cve['id'])
        cve_message = generate_modified_cve_message(modified_cve)
        public_expls_msg = generate_public_expls_message(public_exploits)
        send_slack_mesage(cve_message, public_expls_msg)
        send_telegram_message(cve_message, public_expls_msg)
        send_pushover_message(cve_message, public_expls_msg)
        send_ntfy_message(cve_message, public_expls_msg)

    #Update last times
    update_lasttimes()


if __name__ == "__main__":
    main()
