# This controller is build based on the official Ryu controller: https://github.com/faucetsdn/ryu/tree/master


from operator import attrgetter
from threading import Lock
import os
import time
import sys
from rxoms.utils.amqp_connector import AmqpConnector, AMQPConnectorConfig
from rxoms.utils.rxoms_utils import load_config
import json

# User must export RXOMS_PATH before using
RXOMS_PATH = os.getenv("RXOMS_PATH")
sys.path.append(RXOMS_PATH)
DEFAULT_CONFIG_FILE = RXOMS_PATH + "/configuration/qoa/controller.yaml"
DEFAULT_LOG_FILE = RXOMS_PATH + "/log/controller/report.log"
from ryu.app import rest_firewall
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, packet

import logging

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)

qoa_config = load_config(DEFAULT_CONFIG_FILE)
connector_config = AMQPConnectorConfig.model_validate(qoa_config["connector"]["config"])


class ryuRestFirewall(rest_firewall.RestFirewallAPI):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.report = {}
        self.lock = Lock()
        self.connector = AmqpConnector(connector_config)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match, instructions=inst
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug(
                "packet truncated: only %s of %s bytes",
                ev.msg.msg_len,
                ev.msg.total_len,
            )
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("register datapath: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("unregister datapath: %016x", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.logger.info("Length datapatch: %d", len(self.datapaths.values()))
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
            hub.sleep(5)

    def _request_stats(self, datapath):
        self.logger.debug("send stats request: %016x", datapath.id)
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

        self.logger.info(
            "datapath         "
            "byte-count       "
            "packet-count     "
            "flow-count       "
        )
        self.logger.info(
            "---------------- "
            "---------------- "
            "---------------- "
            "---------------- "
        )
        # for stat in sorted(body, key=attrgetter('packet_count')):
        self.logger.info(
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
        for stat in body:
            if stat.priority == 1:
                try:
                    flow = str(stat.match["in_port"]) + "_" + str(stat.match["eth_dst"])
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow] = {}
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow][
                        "in_port"
                    ] = stat.match["in_port"]
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow][
                        "eth_dst"
                    ] = stat.match["eth_dst"]
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow][
                        "out_port"
                    ] = stat.instructions[0].actions[0].port
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow][
                        "packet_count"
                    ] = stat.packet_count
                    self.report[str(ev.msg.datapath.id)]["FlowStats"][flow][
                        "byte_count"
                    ] = stat.byte_count
                except:
                    self.logger.debug("Flow not exist")
        #             print("Flow not exist")
        # # try:
        #     for stat in sorted([flow for flow in body if flow.priority == 1],
        #                     key=lambda flow: (flow.match['in_port'],
        #                                         flow.match['eth_dst'])):
        #         flow = str(stat.match['in_port'])+"_"+str(stat.match['eth_dst'])
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow] = {}
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["in_port"] = stat.match['in_port']
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["eth_dst"] = stat.match['eth_dst']
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["out_port"] = stat.instructions[0].actions[0].port
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["packet_count"] = stat.packet_count
        #         self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["byte_count"] = stat.byte_count
        # except:
        #     print("error in get flow stats")
        self.lock.release()

        self.logger.info(
            "datapath         " "in-port  eth-dst           " "out-port packets  bytes"
        )
        self.logger.info(
            "---------------- "
            "-------- ----------------- "
            "-------- -------- --------"
        )
        for stat in body:
            try:
                self.logger.info(
                    "%016x %8x %17s %8x %8d %8d",
                    ev.msg.datapath.id,
                    stat.match["in_port"],
                    stat.match["eth_dst"],
                    stat.instructions[0].actions[0].port,
                    stat.packet_count,
                    stat.byte_count,
                )
            except:
                self.logger.debug("Flow not exist")
                # print("Flow not exist")

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

        self.logger.info(
            "datapath         port     "
            "rx-pkts  rx-bytes rx-error "
            "tx-pkts  tx-bytes tx-error"
        )
        self.logger.info(
            "---------------- -------- "
            "-------- -------- -------- "
            "-------- -------- --------"
        )
        for stat in sorted(body, key=attrgetter("port_no")):
            self.logger.info(
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
