import copy
import json
import logging
import os
import traceback
from pathlib import Path

import yaml

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


def get_data_from_response(data_dict: dict):
    try:
        key = next(iter(data_dict.keys()))
        data = data_dict[key]
        return key, data
    except Exception as e:
        logging.error(f"Error when get_data_from_response: {e}")
        logging.error(traceback.format_exc())
        return None, None


def to_json(file_path: str, conf: dict):
    """
    file_path: file path to save config
    """
    with open(file_path, "w") as f:
        json.dump(conf, f)


def to_yaml(file_path: str, conf: dict):
    """
    file_path: file path to save config
    """
    with open(file_path, "w") as f:
        yaml.dump(conf, f, default_flow_style=False)


def load_config(file_path: str) -> dict:
    """
    file_path: file path to load config
    """
    try:
        if "json" in file_path:
            with open(file_path) as f:
                return json.load(f)
        if ("yaml" in file_path) or ("yml" in file_path):
            with open(file_path) as f:
                return yaml.safe_load(f)
        else:
            return None
    except yaml.YAMLError as exc:
        logging.error(exc)


def check_dict_value(udict, key, value):
    if key in udict:
        if udict[key] == value:
            return True
    return False


def get_dict_value(udict, key):
    if key in udict:
        return udict[key]
    return None


def get_physical_twin_from_mac(pt: dict, mac: str):
    for key, value in pt.items():
        if value["mac"] == mac:
            return key, value
    return None, None


def check_gateway(asset_name):
    if "gateway" in asset_name:
        return True
    return False


def get_asset(digital_twin):
    asset = {
        key: value for key, value in digital_twin.items() if value["type"] == "asset"
    }
    return asset


def get_switch(digital_twin):
    switch = {
        key: value for key, value in digital_twin.items() if value["type"] == "switch"
    }
    return switch


def get_gateway(digital_twin):
    gateway = {
        key: value for key, value in digital_twin.items() if value["type"] == "gateway"
    }
    return gateway


def get_attack_mac(digital_twin, asset):
    switch_list = get_switch(digital_twin)
    asset_mac = None
    for key, value in digital_twin.items():
        if key == asset:
            asset_mac = value["mac"]
            print(key)
            break
    switch_mac = None
    in_port = None
    if asset_mac is not None:
        for _swith_key, switch in switch_list.items():
            for port, mac in switch["port"].items():
                if mac == asset_mac:
                    switch_mac = switch["mac"]
                    in_port = port
                    break
    return asset_mac, switch_mac, in_port


def generate_attack_flow(data, attack):
    attack_flow_list = []
    for attaker, attack_data in attack.items():
        attaker_mac, switch_mac, in_port = get_attack_mac(data["digital_twin"], attaker)
        for item in attack_data:
            target_mac, target_switch_mac, out_port = get_attack_mac(
                data["digital_twin"], item["target"]
            )
            print(target_mac, target_switch_mac, out_port)
            attack_nfo = {
                "attakerMac": attaker_mac,
                "switchMac": switch_mac,
                "targetMac": target_mac,
                "tsMac": target_switch_mac,
            }
            attack_nfo.update(item)
            attack_flow_list.append(attack_nfo)
    print(attack_flow_list)


def get_attack_flow(digital_twin, asset):
    switch_list = get_switch(digital_twin)
    asset_list = get_asset(digital_twin)
    asset_mac = None
    for key, value in asset_list.items():
        if key == asset:
            asset_mac = value["mac"]
            break
    attacker_port = []
    if asset_mac is not None:
        for swith_key, switch in switch_list.items():
            for port, mac in switch["port"].items():
                if mac == asset_mac:
                    attacker_port.append(
                        {"switch": swith_key, "port": str(port), "eth_dst": asset_mac}
                    )
                    break
    return attacker_port


def estimate_flow(flow_report, attack_flows, overflow, switch_list):
    flow_data = copy.deepcopy(flow_report)
    attack_flow_list = {}
    normal_flow_ist = {}
    sum_byte_normal_flow = 0
    sum_packet_normal_flow = 0
    for flow_id, flow in flow_data.items():
        switch = flow["switch"]
        in_port = flow["in_port"]
        eth_dst = flow["eth_dst"]
        for attack_flow in attack_flows:
            if (
                "s" + str(switch) == str(attack_flow[0])
                and str(in_port) == str(attack_flow[1])
            ) or (
                "s" + str(switch) == str(attack_flow[0])
                and str(eth_dst) == str(attack_flow[2])
            ):
                attack_flow_list[flow_id] = flow
            else:
                normal_flow_ist[flow_id] = flow
                sum_byte_normal_flow += int(flow["mean_byte_count"])
                sum_packet_normal_flow += int(flow["mean_packet_count"])
    n_attacker = len(attack_flow_list.items())

    for _swith_key, switch in switch_list.items():
        switch["cur_byte"] = int(switch["max_byte"] * float((100 + overflow) / 100))
        switch["cur_packet"] = int(switch["max_packet"] * float((100 + overflow) / 100))
        switch["add_byte"] = int((switch["cur_byte"] - switch["sum_byte"]) / n_attacker)
        switch["add_packet"] = int(
            (switch["cur_packet"] - switch["sum_packet"]) / n_attacker
        )

    for _, flow in attack_flow_list.items():
        flow["mean_byte_count"] += switch_list["s" + str(flow["switch"])]["addByte"]
        flow["mean_packet_count"] += switch_list["s" + str(flow["switch"])]["addPacket"]
        if flow["mean_byte_count"] > switch_list["s" + str(flow["switch"])]["max_byte"]:
            flow["mean_byte_count"] = switch_list["s" + str(flow["switch"])]["max_byte"]
        if (
            flow["mean_packet_count"]
            > switch_list["s" + str(flow["switch"])]["max_packet"]
        ):
            flow["mean_packet_count"] = switch_list["s" + str(flow["switch"])][
                "max_packet"
            ]

    for _, flow in normal_flow_ist.items():
        if overflow > 0:
            minus_byte = (
                switch_list["s" + str(flow["switch"])]["cur_byte"]
                - switch_list["s" + str(flow["switch"])]["max_byte"]
            )
            minus_packet = (
                switch_list["s" + str(flow["switch"])]["cur_packet"]
                - switch_list["s" + str(flow["switch"])]["max_packet"]
            )
            flow["mean_byte_count"] -= minus_byte * (
                flow["mean_byte_count"] / sum_byte_normal_flow
            )
            flow["mean_packet_count"] -= minus_packet * (
                flow["mean_packet_count"] / sum_packet_normal_flow
            )
            if flow["mean_byte_count"] < 0:
                flow["mean_byte_count"] = 0
            if flow["mean_packet_count"] < 0:
                flow["mean_packet_count"] = 0
    updated_flow = {}
    updated_flow.update(attack_flow_list)
    updated_flow.update(normal_flow_ist)
    return updated_flow


def get_flow(flow_data, switch, in_port, eth_dst):
    for key, value in flow_data.items():
        if (
            (str(value["switch"]) == str(switch))
            and (str(value["in_port"]) == str(in_port))
            and (str(value["eth_dst"]) == str(eth_dst))
        ):
            return key, value
    return None, None


def filter_dict(flow_data, filter_key, filter_value):
    filtered_flow = {}
    for key, value in flow_data.items():
        if str(value[filter_key]) == str(filter_value):
            filtered_flow[key] = value
    return filtered_flow


def select_from_dict(flow_data, filter_key, filter_value):
    for key, value in flow_data.items():
        if value[filter_key] == filter_value:
            return key, value
    return None, None


def check_overflow(flow_data, switch):
    sum_byte_flow = 0
    sum_packet_flow = 0
    overflow = {"byte": 0, "packet": 0, "overflow": 0}
    for _, flow in flow_data.items():
        if flow["recent_byte_value"] > 0:
            sum_byte_flow += flow["recent_byte_value"]
        else:
            sum_byte_flow += flow["mean_byte_count"]
        if flow["recent_packet_value"] > 0:
            sum_packet_flow += flow["recent_packet_value"]
        else:
            sum_packet_flow += flow["mean_packet_count"]

    if sum_byte_flow > switch["max_byte"]:
        overflow["byte"] = sum_byte_flow - switch["max_byte"]
        overflow["overflow"] = 1
    if sum_packet_flow > switch["max_packet"]:
        overflow["packet"] = sum_packet_flow - switch["max_packet"]
        overflow["overflow"] = 1
    return overflow


def df_to_csv(file_path, df):
    df.to_csv(file_path, mode="a", header=not os.path.exists(file_path))


def get_parent_directory(path, n):
    p = Path(path).resolve()
    for _ in range(n):
        p = p.parent
    return p
