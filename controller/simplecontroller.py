# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from qoa4ml.QoaClient import QoaClient
from qoa4ml import qoaUtils
from threading import Lock

lib_path = qoaUtils.get_parent_dir(__file__,1)
config_folder = lib_path+"/configuration/"
config_file = qoaUtils.load_config(config_folder+"qoaConfig.yaml")


class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.report = {}
        self.lock = Lock()
        # self.qoa_client = QoaClient(config_dict=config_file, registration_url=config_file["registration_url"])
        # print(self.qoa_client.configuration)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.log_report = config_file["log_report"]
        
        


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.logger.info("Length datapatch: %d", len(self.datapaths.values()))
            for dp in self.datapaths.values():
                self._request_stats(dp)
            # self.logger.info(str(self.report))
            with open(self.log_report, 'a+') as f:
                if self.report:
                    f.write(str(self.report)+"\n")
            # self.qoa_client.report(report=self.report, submit=False)
            hub.sleep(1)


    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        cookie = cookie_mask = 0
        match = parser.OFPMatch(in_port=1)
        req = parser.OFPAggregateStatsRequest(datapath, 0,
                                                ofproto.OFPTT_ALL,
                                                ofproto.OFPP_ANY,
                                                ofproto.OFPG_ANY,
                                                cookie, cookie_mask,
                                                match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def _flow_agg_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()
        
        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["Aggregate"] = {}
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["byte_count"] = body.byte_count
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["packet_count"] = body.packet_count
        self.report[str(ev.msg.datapath.id)]["Aggregate"]["flow_count"] = body.flow_count
        self.lock.release()

        self.logger.info('datapath         '
                         'byte-count       '
                         'packet-count     '
                         'flow-count       ')
        self.logger.info('---------------- '
                         '---------------- '
                         '---------------- '
                         '---------------- ')
        # for stat in sorted(body, key=attrgetter('packet_count')):
        self.logger.info('%016x %16d %16d %16d',
                            ev.msg.datapath.id,
                            body.byte_count,
                            body.packet_count, body.flow_count)
        

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()
        
        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["FlowStats"] = {}
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            flow = str(stat.match['in_port'])+"_"+str(stat.match['eth_dst'])
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow] = {}
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["in_port"] = stat.match['in_port']
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["eth_dst"] = stat.match['eth_dst']
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["out_port"] = stat.instructions[0].actions[0].port
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["packet_count"] = stat.packet_count
            self.report[str(ev.msg.datapath.id)]["FlowStats"][flow]["byte_count"] = stat.byte_count
        self.lock.release()

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.lock.acquire()
        if str(ev.msg.datapath.id) not in self.report:
            self.report[str(ev.msg.datapath.id)] = {}
        self.report[str(ev.msg.datapath.id)]["PortStats"] = {}

        for stat in sorted(body, key=attrgetter('port_no')):
            port = str(stat.port_no)
            self.report[str(ev.msg.datapath.id)]["PortStats"][port] = {}
            # self.report[str(ev.msg.datapath.id)]["PortStats"]["port_no"] = stat.port_no
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_packets"] = stat.rx_packets
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_bytes"] = stat.rx_bytes
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["rx_errors"] = stat.rx_errors
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_packets"] = stat.tx_packets
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_bytes"] = stat.tx_bytes
            self.report[str(ev.msg.datapath.id)]["PortStats"][port]["tx_errors"] = stat.tx_errors
        
        self.lock.release()



        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)