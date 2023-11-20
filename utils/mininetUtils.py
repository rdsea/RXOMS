from threading import Thread, Lock
import random, time, os, logging
import pandas as pd
from threading import Thread, Lock
logging.basicConfig(format='%(asctime)s:%(levelname)s -- %(message)s', level=logging.INFO)
from soarUtils import to_yaml

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
    ip_config = {}
    switch_config = {}

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
                ip_config[host_name] = host_dict[host_name]["host"].IP()
            # Set data file for each host
            if host_name.upper() in str(csvFile):
                if "MQTT" in str(csvFile):
                    host_dict[host_name]["mqtt"] = csvFile
                if "OPC-UA" in str(csvFile):
                    host_dict[host_name]["opc"] = csvFile
    to_yaml('ip_config.yml', ip_config)
    switches = net.switches
    for switch in switches:
        switch_config[switch.dpid] = switch.name
    print(switch_config)
    to_yaml('switch_config.yml', switch_config)
    # Generate traffic in sub-thread from each host
    for host in host_dict:
        thread_i = Thread(target=h2hTraffic, kwargs=(host_dict[host]))
        thread_i.start()
    
    time.sleep(10)
    logging.info("Stopping traffic...")
    logging.info("Killing active iperf sessions...")


    for host in net.hosts:
        host.cmdPrint('killall -9 iperf')