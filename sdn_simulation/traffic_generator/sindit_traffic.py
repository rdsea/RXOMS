import logging
import os
import random
import time
from threading import Lock, Thread
from mininet.topo import Topo
import pandas as pd

from rxoms.utils.rxoms_utils import to_yaml

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


class SinditTopo(Topo):
    "Simple star topology with single switch and 12 hosts"

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches
        host_ssc = self.addHost("ssc")
        host_mpo = self.addHost("mpo")
        host_sld = self.addHost("sld")
        host_hbw = self.addHost("hbw")
        host_dps = self.addHost("dps")
        host_vgr = self.addHost("vgr")
        mqtt_gateway = self.addHost("mqttgw")
        opcua_gateway = self.addHost("opcuagw")
        mqtt_switch = self.addSwitch("s1")
        opcua_switch = self.addSwitch("s2")

        # Add links
        self.addLink(host_mpo, mqtt_switch)
        self.addLink(host_sld, mqtt_switch)
        self.addLink(host_dps, mqtt_switch)
        # self.addLink( host_ssc, mqtt_switch )
        # self.addLink( host_vgr, mqtt_switch )
        # self.addLink( host_hbw, mqtt_switch )
        self.addLink(mqtt_gateway, mqtt_switch)
        self.addLink(opcua_gateway, opcua_switch)
        self.addLink(mqtt_switch, opcua_switch)
        self.addLink(host_ssc, opcua_switch)
        self.addLink(host_vgr, opcua_switch)
        self.addLink(host_hbw, opcua_switch)


topos = {"startopo": (lambda: SinditTopo())}


# Default value
lock_dict = {"mqttgw": Lock(), "opcuagw": Lock()}
port_min = 1025
port_max = 65536
sampling_interval = "1"  # seconds


def generate_custom_traffic(src, dst, bandwidth, log):
    protocol = "--udp"
    # port_argument = str(get_port(str(src.name)))
    port_argument = str(random.randint(port_min, port_max))

    # create client cmd
    cmd_clt = "iperf -c "
    cmd_clt += dst.IP() + " "
    cmd_clt += protocol
    cmd_clt += " -p "
    cmd_clt += port_argument
    if protocol == "--udp":
        cmd_clt += " -b "
        cmd_clt += bandwidth
    cmd_clt += " -t "
    cmd_clt += "1"
    cmd_clt += " & "
    # Send client command from source host
    src.cmdPrint(cmd_clt)

    # create server cmd
    cmd_serv = "iperf -s "
    cmd_serv += "--udp"
    cmd_serv += " -p "
    cmd_serv += port_argument
    cmd_serv += " -i "
    cmd_serv += sampling_interval
    cmd_serv += " >> "
    cmd_serv += log + "/flow_" + str(dst.name) + ".txt"
    cmd_serv += " & "
    dst_lock = lock_dict[dst.name]

    # Lock and send cmd from dest host (Server)
    dst_lock.acquire()
    dst.cmdPrint(cmd_serv)
    dst_lock.release()


def h2h_traffic(**kwargs):
    # Generat traffic from host to host
    source = kwargs["host"]
    net = kwargs["net"]
    log_dir = kwargs["log"]
    data_path = kwargs["data_path"]
    mqtt_data = None
    opc_data = None
    max_len = 0

    # Read Mqtt data if exist
    if "mqtt" in kwargs:
        file_path = data_path + kwargs["mqtt"]
        mqtt_data = pd.read_csv(file_path)
        if len(mqtt_data.index) > max_len:
            max_len = len(mqtt_data.index)

    # Read OPC-UA data if exist
    if "opc" in kwargs:
        file_path = data_path + kwargs["opc"]
        opc_data = pd.read_csv(file_path)
        if len(opc_data.index) > max_len:
            max_len = len(opc_data.index)

    for i in range(max_len):
        try:
            # Generate data flow to MQTT gateway
            if isinstance(mqtt_data, pd.DataFrame):
                if i < len(mqtt_data.index):
                    row_data = mqtt_data.iloc[i]
                    bandwidth = str(int(row_data["flow"])) + "K"
                    generate_custom_traffic(
                        src=source,
                        dst=net.get("mqttgw"),
                        bandwidth=bandwidth,
                        log=log_dir,
                    )
            # Generate data flow to OPC-UA gateway
            if isinstance(opc_data, pd.DataFrame):
                if i < len(opc_data.index):
                    row_data = opc_data.iloc[i]
                    bandwidth = str(int(row_data["flow"])) + "K"
                    generate_custom_traffic(
                        src=source,
                        dst=net.get("opcuagw"),
                        bandwidth=bandwidth,
                        log=log_dir,
                    )
            # Wait for flow end
            time.sleep(15)
        except Exception as e:
            logging.error(f"Error in h2hTraffic: {e}")


def generate_traffic(net, data_path, log_dir, config_path):
    # Get hosts from simulated network
    hosts = net.hosts
    # dictionary storing host's configuration
    host_dict = {}
    ip_config = {}
    switch_config = {}

    # Get list of data files
    file_list = os.listdir(data_path)

    for csv_file in file_list:
        for host in hosts:
            host_name = host.name
            # Init host configuration
            if host_name not in host_dict:
                host_dict[host_name] = {}
                host_dict[host_name]["host"] = net.get(str(host_name))
                host_dict[host_name]["net"] = net
                host_dict[host_name]["log"] = log_dir
                host_dict[host_name]["data_path"] = data_path
                ip_config[host_name] = host_dict[host_name]["host"].IP()
            # Set data file for each host
            if host_name.upper() in str(csv_file):
                if "MQTT" in str(csv_file):
                    host_dict[host_name]["mqtt"] = csv_file
                if "OPC-UA" in str(csv_file):
                    host_dict[host_name]["opc"] = csv_file
    to_yaml(config_path + "ip_config.yml", ip_config)
    switches = net.switches
    for switch in switches:
        switch_config[switch.dpid] = switch.name
    to_yaml(config_path + "switch_config.yml", switch_config)
    # Generate traffic in sub-thread from each host
    for host in host_dict:
        thread_i = Thread(target=h2h_traffic, kwargs=(host_dict[host]))
        thread_i.start()

    time.sleep(10)
    logging.info("Stopping traffic...")
    logging.info("Killing active iperf sessions...")

    for host in net.hosts:
        host.cmdPrint("killall -9 iperf")
