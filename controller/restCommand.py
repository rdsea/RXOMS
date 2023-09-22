import requests, argparse, json, logging, pathlib, yaml
import sys
sys.path.append("..")
from soarUtils import *
current_path = str(pathlib.Path(__file__).parent.absolute())
logging.basicConfig(format='%(asctime)s:%(levelname)s -- %(message)s', level=logging.INFO)

status_url = 'firewall/module/status'
enable_url = 'firewall/module/enable/'
disable_url = 'firewall/module/disable/'
rule_url = 'firewall/rules/'

# mqtt_ip_list = ["10.0.0.1/32",
#                 "10.0.0.2/32",
#                 "10.0.0.3/32",
#                 "10.0.0.4/32",
#                 "10.0.0.6/32",
#                 "10.0.0.7/32",
#                 "10.0.0.8/32"]
# opcua_ip_list = ["10.0.0.2/32",
#                 "10.0.0.5/32",
#                 "10.0.0.7/32",
#                 "10.0.0.8/32"]
# ip_list = {}
# ip_list['s1'] = mqtt_ip_list
# ip_list['s2'] = opcua_ip_list

ip_list = ["10.0.0.1/32",
            "10.0.0.2/32",
            "10.0.0.3/32",
            "10.0.0.4/32",
            "10.0.0.5/32",
            "10.0.0.6/32",
            "10.0.0.7/32",
            "10.0.0.8/32"]



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

def allow_all(url, switch_id, topo_config, ip_config, switch_config, protocol):
    switch_key = switch_config[switch_id]
    switch = topo_config[switch_key]
    for key in list(switch.keys()):
        dst_ip = ip_config[key]
        src_ip_list = switch[key]
        for src_ip in src_ip_list:
            data = {"nw_proto": protocol,
                    "dl_type": "IPv4",
                    "nw_src": src_ip,
                    "nw_dst": dst_ip,
                    "actions": "ALLOW"}
            rule = add_rule(url, switch_id, rule=data)
            logging.info(rule)
            data = {"nw_proto": protocol,
                    "dl_type": "IPv4",
                    "nw_src": dst_ip,
                    "nw_dst": src_ip,
                    "actions": "ALLOW"}
            rule = add_rule(url, switch_id, rule=data)
            logging.info(rule)

def allow_allv2(url, switch_id, protocol):
    for i in range(len(ip_list)):
        for j in range(i+1,len(ip_list)):
            data = {"nw_proto": protocol,
                    "dl_type": "IPv4",
                    "nw_src": ip_list[i],
                    "nw_dst": ip_list[j],
                    "actions": "ALLOW"}
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
    switch_config = load_config('../switch_config.yml')
    ip_config = load_config('../ip_config.yml')
    topo_config = load_config('../topo.yml')

    if isinstance(fw_status, list):
        for switch in fw_status:
            switch_id = switch["switch_id"]
            fw_enable = enable_fw(enable_url, switch_id)
            logging.info(fw_enable)
            # allow_all(rule_url, switch_id, topo_config, ip_config, switch_config, "UDP")
            # allow_all(rule_url, switch_id, topo_config, ip_config, switch_config, "ICMP")
            # allow_all(rule_url, switch_id, topo_config, ip_config, switch_config, "TCP")
            allow_allv2(rule_url, switch_id, "UPD")
            allow_allv2(rule_url, switch_id, "ICMP")
            allow_allv2(rule_url, switch_id, "TCP")