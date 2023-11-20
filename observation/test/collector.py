from qoa4ml import qoaUtils as utils
from qoa4ml.collector.amqp_collector import Amqp_Collector
import sys, argparse
lib_path = utils.get_parent_dir(__file__,2)
config_folder = lib_path+"/configuration/"


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Node Monitoring")
    parser.add_argument('--conf', help='configuration file', default="collector.json")
    args = parser.parse_args()

    config_file = config_folder+args.conf
    collector_conf = utils.load_config(config_file)
    print(collector_conf)
    collector = Amqp_Collector(collector_conf["conf"])
    collector.start()
    # a = __import__("qoa4ml.collector.amqp_collector")
    # print(a)
