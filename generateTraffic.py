from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, DefaultController
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import pandas as pd
from threading import Thread, Lock
import logging
from topology.factoryTopo import SinditTopo
from os import path
from os import mkdir
import random
import time, argparse, pathlib
import sys, os
import re
import numpy as np

current_path = str(pathlib.Path(__file__).parent.absolute())
logging.basicConfig(format='%(asctime)s:%(levelname)s -- %(message)s', level=logging.INFO)

# Default value
lock_dict = {
    "mqttgw": Lock(),
    "opcuagw": Lock()
}
port_min = 1025
port_max = 65536
sampling_interval = '1'  # seconds



def generate_custom_traffic(src, dst, bandwith, log):

    protocol = '--udp'
    # port_argument = str(get_port(str(src.name)))
    port_argument = str(random.randint(port_min, port_max))

    # create client cmd
    cmdClt = "iperf -c "
    cmdClt += dst.IP() + " "
    cmdClt += protocol
    cmdClt += " -p "
    cmdClt += port_argument
    if protocol == "--udp":
        cmdClt += " -b "
        cmdClt += bandwith
    cmdClt += " -t "
    cmdClt += "1"
    cmdClt += " & "
    # Send client command from source host
    src.cmdPrint(cmdClt)

    # create server cmd
    cmdServ = "iperf -s "
    cmdServ += '--udp'
    cmdServ += " -p "
    cmdServ += port_argument
    cmdServ += " -i "
    cmdServ += sampling_interval
    cmdServ += " >> "
    cmdServ += log + "/flow_" + str(dst.name) + ".txt"
    cmdServ += " & "
    dst_lock = lock_dict[dst.name]

    # Lock and send cmd from dest host (Server)
    dst_lock.acquire()
    dst.cmdPrint(cmdServ)
    dst_lock.release()

def h2hTraffic(**kwargs):
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
        file_path = data_path+kwargs["mqtt"]
        mqtt_data = pd.read_csv(file_path)
        if len(mqtt_data.index) > max_len:
            max_len = len(mqtt_data.index)

    # Read OPC-UA data if exist
    if "opc" in kwargs:
        file_path = data_path+kwargs["opc"]
        opc_data = pd.read_csv(file_path)
        if len(opc_data.index) > max_len:
            max_len = len(opc_data.index) 

    for i in range(max_len):
        try:
            # Generate data flow to MQTT gateway
            if isinstance(mqtt_data, pd.DataFrame):
                if i < len(mqtt_data.index):
                    row_data = mqtt_data.iloc[i]
                    bandwidth = str(int(row_data["flow"]))+"K"
                    generate_custom_traffic(src=source, dst= net.get(str("mqttgw")), bandwith=bandwidth, log=log_dir)
            # Generate data flow to OPC-UA gateway
            if isinstance(opc_data, pd.DataFrame):
                if i < len(opc_data.index):
                    row_data = opc_data.iloc[i]
                    bandwidth = str(int(row_data["flow"]))+"K"
                    generate_custom_traffic(src=source, dst= net.get(str("opcuagw")), bandwith=bandwidth, log=log_dir)
            # Wait for flow end
            time.sleep(1)
        except Exception as e:
            logging.error("Error in h2hTraffic: {}".format(e))




def generate_traffic(net, data_path, log_dir):
    # Get hosts from simulated network
    hosts = net.hosts
    # dictionary storing host's configuration
    host_dict = {}

    # Get list of data files
    file_list = os.listdir(data_path)
    
    for csvFile in file_list:
        for host in hosts:
            host_name = host.name
            # Init host configuration
            if host_name not in host_dict:
                host_dict[host_name] = {}
                host_dict[host_name]["host"] = net.get(str(host_name))
                host_dict[host_name]["net"] = net
                host_dict[host_name]["log"] = log_dir
                host_dict[host_name]["data_path"] = data_path
            # Set data file for each host
            if host_name.upper() in str(csvFile):
                if "MQTT" in str(csvFile):
                    host_dict[host_name]["mqtt"] = csvFile
                if "OPC-UA" in str(csvFile):
                    host_dict[host_name]["opc"] = csvFile
    
    # Generate traffic in sub-thread from each host
    for host in host_dict:
        thread_i = Thread(target=h2hTraffic, kwargs=(host_dict[host]))
        thread_i.start()
        thread_i.join()
    
    time.sleep(10)
    info("Stopping traffic...\n")
    info("Killing active iperf sessions...\n")

    for host in net.hosts:
        host.cmdPrint('killall -9 iperf')



# Main function
if __name__ == "__main__":
    # Loading default parameter values
    parser = argparse.ArgumentParser(description="Processing SINDIT Data")
    parser.add_argument('--log', help='category file', default="/log/")
    parser.add_argument('--ctr', help='controller IP', default="127.0.0.1")
    parser.add_argument('--ctrp', help='controller port', default=6633)
    parser.add_argument('--dc', help='default controller', default="False")
    parser.add_argument('--df', help='debug flag', default="False")
    parser.add_argument('--dh', help='debug host', default="127.0.0.1")
    parser.add_argument('--dp', help='debug port', default=6000)
    parser.add_argument('--data', help='data folder', default="/data/")
    
    
    # Parse the parameters
    args = parser.parse_args()
    log_dir = current_path+args.log
    default_controller = bool(args.dc)
    controller_ip = args.ctr  
    controller_port = args.ctrp
    debug_flag = bool(args.df)
    debug_host = args.dh
    debug_port = 6000
    data_path = current_path+args.data

    setLogLevel('info')

    topology = SinditTopo()

    # creating log directory    
    i = 1
    while True:
        if not path.exists(log_dir + "log_"+str(i)):
            log_dir = log_dir + "log_"+str(i)
            mkdir(log_dir)
            break
        i = i+1
    


    # starting mininet
    print(default_controller)
    if default_controller:
        # net = Mininet(topo=topology, controller=DefaultController, host=CPULimitedHost, link=TCLink,
        #               switch=OVSSwitch, autoSetMacs=True)
        net = Mininet(topo=topology, controller=None, host=CPULimitedHost, link=TCLink,
                      switch=OVSSwitch, autoSetMacs=True)
        net.addController('c1', controller=RemoteController, ip=controller_ip, port=controller_port)
    else:
        net = Mininet(topo=topology, controller=None, host=CPULimitedHost, link=TCLink,
                      switch=OVSSwitch, autoSetMacs=True)
        net.addController('c1', controller=RemoteController, ip=controller_ip, port=controller_port)

    net.start()
    # Start generating traffic 
    generate_traffic(net, data_path, log_dir)