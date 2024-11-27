# This controller is build based on the official Ryu controller: https://github.com/faucetsdn/ryu/tree/master

import logging
import os
import time
import sys
from operator import attrgetter
from threading import Lock
from rxoms.utils.amqp_connector import AmqpConnector, AMQPConnectorConfig
from rxoms.utils.rxoms_utils import load_config
import json

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
# User must export RXOMS_PATH before using
RXOMS_PATH = os.getenv("RXOMS_PATH")
sys.path.append(RXOMS_PATH)
DEFAULT_CONFIG_FILE = RXOMS_PATH + "/configuration/qoa/controller.yaml"
DEFAULT_LOG_FILE = RXOMS_PATH + "/log/controller/report.log"

qoa_config = load_config(DEFAULT_CONFIG_FILE)
connector_config = AMQPConnectorConfig.model_validate(qoa_config["connector"]["config"])


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.report = {}
        self.lock = Lock()
        self.connector = AmqpConnector(connector_config)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.log_report = DEFAULT_LOG_FILE

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                logging.info("register datapath: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                logging.info("unregister datapath: %016x", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            logging.info("Length datapatch: %d", len(self.datapaths.values()))
            for dp in self.datapaths.values():
                self._request_stats(dp)
            stats = self.report
            report = {"client": qoa_config["client"], "stats": stats}
            report["client"]["timestamp"] = time.time()
            logging.info(str(report))
            with open(self.log_report, "a+") as f:
                if report:
                    f.write(str(report) + "\n")
            self.connector.send_report(body_message=json.dumps(report).encode("utf-8"))
            hub.sleep(1)

    def _request_stats(self, datapath):
        logging.debug("send stats request: %016x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        cookie = cookie_mask = 0
        match = parser.OFPMatch(in_port=1)
        req = parser.OFPAggregateStatsRequest(
            datapath,
            0,
            ofproto.OFPTT_ALL,
            ofproto.OFPP_ANY,
            ofproto.OFPG_ANY,
            cookie,
            cookie_mask,
            match,
        )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def _flow_agg_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()

        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["Aggregate"] = {}
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["byte_count"] = (
            body.byte_count
        )
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["packet_count"] = (
            body.packet_count
        )
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["flow_count"] = (
            body.flow_count
        )
        self.lock.release()

        logging.info(
            "datapath         "
            "byte-count       "
            "packet-count     "
            "flow-count       "
        )
        logging.info(
            "---------------- "
            "---------------- "
            "---------------- "
            "---------------- "
        )
        # for stat in sorted(body, key=attrgetter('packet_count')):
        logging.info(
            "%016x %16d %16d %16d",
            ev.msg.datapath.id,
            body.byte_count,
            body.packet_count,
            body.flow_count,
        )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()

        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["FlowStats"] = {}
        for stat in sorted(
            [flow for flow in body if flow.priority == 1],
            key=lambda flow: (flow.match["in_port"], flow.match["eth_dst"]),
        ):
            flow = str(stat.match["in_port"]) + "_" + str(stat.match["eth_dst"])
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow] = {}
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["in_port"] = (
                stat.match["in_port"]
            )
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["eth_dst"] = (
                stat.match["eth_dst"]
            )
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["out_port"] = (
                stat.instructions[0].actions[0].port
            )
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["packet_count"] = (
                stat.packet_count
            )
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["byte_count"] = (
                stat.byte_count
            )
        self.lock.release()

        logging.info(
            "datapath         " "in-port  eth-dst           " "out-port packets  bytes"
        )
        logging.info(
            "---------------- "
            "-------- ----------------- "
            "-------- -------- --------"
        )
        for stat in sorted(
            [flow for flow in body if flow.priority == 1],
            key=lambda flow: (flow.match["in_port"], flow.match["eth_dst"]),
        ):
            logging.info(
                "%016x %8x %17s %8x %8d %8d",
                ev.msg.datapath.id,
                stat.match["in_port"],
                stat.match["eth_dst"],
                stat.instructions[0].actions[0].port,
                stat.packet_count,
                stat.byte_count,
            )

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()
        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["PortStats"] = {}

        for stat in sorted(body, key=attrgetter("port_no")):
            port = str(stat.port_no)
            self.report[str(ev.msg.datapath.id)]["PortStats"][port] = {}
            # self.report[str(ev.msg.datapath.id)]["PortStats"]["port_no"] = stat.port_no
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_packets"] = (
                stat.rx_packets
            )
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_bytes"] = (
                stat.rx_bytes
            )
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_errors"] = (
                stat.rx_errors
            )
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_packets"] = (
                stat.tx_packets
            )
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_bytes"] = (
                stat.tx_bytes
            )
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_errors"] = (
                stat.tx_errors
            )

        self.lock.release()

        logging.info(
            "datapath         port     "
            "rx-pkts  rx-bytes rx-error "
            "tx-pkts  tx-bytes tx-error"
        )
        logging.info(
            "---------------- -------- "
            "-------- -------- -------- "
            "-------- -------- --------"
        )
        for stat in sorted(body, key=attrgetter("port_no")):
            logging.info(
                "%016x %8x %8d %8d %8d %8d %8d %8d",
                ev.msg.datapath.id,
                stat.port_no,
                stat.rx_packets,
                stat.rx_bytes,
                stat.rx_errors,
                stat.tx_packets,
                stat.tx_bytes,
                stat.tx_errors,
            )
