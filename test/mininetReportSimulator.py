import sys, os, argparse
MLSOAR_PATH = os.getenv("MLSOAR_PATH")
sys.path.append(MLSOAR_PATH)

log_path = MLSOAR_PATH + "/log/report/"


# Main function
if __name__ == "__main__":
    # Loading default parameter values
    parser = argparse.ArgumentParser(description="Generate ")
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
    log_dir = MLSOAR_PATH+args.log
    default_controller = bool(args.dc)
    controller_ip = args.ctr  
    controller_port = args.ctrp
    debug_flag = bool(args.df)
    debug_host = args.dh
    debug_port = 6000
    data_path = MLSOAR_PATH+args.data