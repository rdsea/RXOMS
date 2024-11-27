import argparse
import logging
import os
import sys
from os import mkdir, path

from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import CPULimitedHost, OVSSwitch, RemoteController

RXOMS_PATH = os.getenv("RXOMS_PATH")
sys.path.append(RXOMS_PATH)
from sindit_traffic import generate_traffic
from sindit_traffic import SinditTopo


logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


# Main function
if __name__ == "__main__":
    # Loading default parameter values
    parser = argparse.ArgumentParser(description="Generate Mininet Traffic")
    parser.add_argument("--log", help="category file", default="/log/sdn_simulation/")
    parser.add_argument("--ctr", help="controller IP", default="127.0.0.1")
    parser.add_argument("--ctrp", help="controller port", default=6633)
    parser.add_argument("--dc", help="default controller", default="False")
    parser.add_argument("--df", help="debug flag", default="False")
    parser.add_argument("--dh", help="debug host", default="127.0.0.1")
    parser.add_argument("--dp", help="debug port", default=6000)
    parser.add_argument("--data", help="data folder", default="/data/normalizedDT/")
    parser.add_argument(
        "--cp", help="configure path", default="/configuration/network/"
    )

    # Parse the parameters
    args = parser.parse_args()
    log_dir = RXOMS_PATH + args.log
    default_controller = bool(args.dc)
    controller_ip = args.ctr
    controller_port = args.ctrp
    debug_flag = bool(args.df)
    debug_host = args.dh
    debug_port = 6000
    data_path = RXOMS_PATH + args.data
    config_path = RXOMS_PATH + args.cp

    setLogLevel("info")
    topology = SinditTopo()

    # creating log directory
    i = 1
    while True:
        if not path.exists(log_dir + "log_" + str(i)):
            log_dir = log_dir + "log_" + str(i)
            mkdir(log_dir)
            break
        i = i + 1

    # starting mininet
    if default_controller:
        # net = Mininet(topo=topology, controller=DefaultController, host=CPULimitedHost, link=TCLink,
        #               switch=OVSSwitch, autoSetMacs=True)
        net = Mininet(
            topo=topology,
            controller=None,
            host=CPULimitedHost,
            link=TCLink,
            switch=OVSSwitch,
            autoSetMacs=True,
        )
        net.addController(
            "c1", controller=RemoteController, ip=controller_ip, port=controller_port
        )
    else:
        net = Mininet(
            topo=topology,
            controller=None,
            host=CPULimitedHost,
            link=TCLink,
            switch=OVSSwitch,
            autoSetMacs=True,
        )
        net.addController(
            "c1", controller=RemoteController, ip=controller_ip, port=controller_port
        )

    net.start()
    # Start generating traffic
    generate_traffic(net, data_path, log_dir, config_path)
