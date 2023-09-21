import requests, argparse, json, logging, pathlib
current_path = str(pathlib.Path(__file__).parent.absolute())
logging.basicConfig(format='%(asctime)s:%(levelname)s -- %(message)s', level=logging.INFO)

status_url = 'firewall/module/status'
enable_url = 'firewall/module/enable/'
disable_url = 'firewall/module/disable/'
rule_url = 'firewall/rules/'

ip_list = ["10.0.0.1/32",
           "10.0.0.2/32",
           "10.0.0.3/32",
           "10.0.0.4/32",
           "10.0.0.5/32",
           "10.0.0.6/32",
           "10.0.0.7/32",
           "10.0.0.8/32",]


headers = {"Content-Type": "application/json"}


def get_fw_status(url):
    try:
        return requests.get(url, headers=headers).json()
    except Exception as e:
        logging.error("Error while getting firewall status: {}".format(e))

def enable_fw(url, switch_id):
    try:
        return requests.put(url+switch_id, headers=headers).json()
    except Exception as e:
        logging.error("Error while enabling firewall: {}".format(e))

def add_rule(url, switch_id, rule):
    try:
        return requests.post(url+switch_id, json=rule,headers=headers).json()
    except Exception as e:
        logging.error("Error while add rule to firewall: {}".format(e))

def allow_all(url, switch_id, ip_list, protocol):
    for ip in ip_list:
        data = {"nw_proto": protocol,
                "nw_src": ip}
        rule = add_rule(url, switch_id, rule=data)
        logging.info(rule)
        data = {"nw_proto": protocol,
                "nw_dst": ip}
        rule = add_rule(url, switch_id, rule=data)
        logging.info(rule)
# Main function
if __name__ == "__main__":
    # Loading default parameter values
    parser = argparse.ArgumentParser(description="Interact with firewall")
    parser.add_argument('--url', help='Firewall rest server', default="http://0.0.0.0:8080/")
    args = parser.parse_args()

    status_url = args.url+status_url
    enable_url = args.url+enable_url
    disable_url = args.url+disable_url
    rule_url = args.url+rule_url

    fw_status = get_fw_status(status_url)
    logging.info(fw_status)

    if isinstance(fw_status, list):
        for switch in fw_status:
            switch_id = switch["switch_id"]
            fw_enable = enable_fw(enable_url, switch_id)
            logging.info(fw_enable)
            allow_all(rule_url, switch_id, ip_list, "UDP")

        
    