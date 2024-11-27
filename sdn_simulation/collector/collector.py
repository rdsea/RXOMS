import argparse
import logging
import os
import sys
import json
import pandas as pd
from collections.abc import MutableMapping


from rxoms.utils.amqp_collector import AmqpCollector
from rxoms.utils.amqp_collector import AMQPCollectorConfig
from rxoms.utils.rxoms_utils import load_config

RXOMS_PATH = os.getenv("RXOMS_PATH")
sys.path.append(RXOMS_PATH)


def message_handling(body_dict, file_path=None):
    logging.info("Received message: %s", body_dict)
    for switch, stats in body_dict["stats"].items():
        flow_stats = stats["FlowStats"]
        for flow, flow_stat in flow_stats.items():
            flow_stat["switch"] = switch
            flow_stat.update(body_dict["client"])
            df = pd.DataFrame([flow_stat])
            if os.path.isfile(file_path):
                df.to_csv(file_path, mode="a", header=False, index=False)
            else:
                df.to_csv(file_path, mode="w", header=True, index=False)


class DataHandler:
    def __init__(self, file_path=None) -> None:
        if file_path is not None:
            self.file_path = file_path

    def message_processing(self, ch, method, props, body):
        json_str = body.decode("utf-8")
        body_dict = json.loads(json_str)
        message_handling(body_dict, file_path=self.file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Node Monitoring")
    parser.add_argument(
        "--conf", help="configuration file", default="/configuration/qoa/collector.yaml"
    )
    parser.add_argument(
        "--out", help="output file", default="/data/sdn_simulation/raw_message.csv"
    )

    args = parser.parse_args()
    conf = load_config(RXOMS_PATH + args.conf)
    file_path = RXOMS_PATH + args.out
    ampq_conf = AMQPCollectorConfig(**conf)
    handler = DataHandler(file_path)
    collector = AmqpCollector(configuration=ampq_conf, host_object=handler)
    collector.start_collecting()
