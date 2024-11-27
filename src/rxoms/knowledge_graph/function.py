import logging
import time
import traceback
import pymongo
from pymongo.server_api import ServerApi
from rxoms.base_model import (
    RxomsCTI,
    RxomsDetector,
    RxomsDT,
    RxomsDTType,
    RxomsFlow,
    RxomsFlowStatus,
    RxomsLogicalReport,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsSwitch,
)
from rxoms.utils.rxoms_utils import get_data_from_response

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


def init_graph_in_db(graph_data: dict, mongo_config: dict, credentials: dict):
    logging.info(f"config: {mongo_config}, credentials: {credentials}")
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            logging.info(f"Connected to MongoDB successfully")
            db = mongo_client[mongo_config["db"]]
                    
            cti_collection = db[mongo_config["collection"]["cti"]]
            for key,value in graph_data["cti"].items():
                data = {"_key": key, "mitigation": value, "timestamp": time.time()}
                cti_collection.insert_one(data)
            
            dt_collection = db[mongo_config["collection"]["dt"]]
            for key,value in graph_data["digital_twin"].items():
                value["_key"] = key
                value["timestamp"] = time.time()
                dt_collection.insert_one(value)
            
            flow_collection = db[mongo_config["collection"]["flow"]]
            for key,value in graph_data["flow"].items():
                value["_key"] = key
                value["timestamp"] = time.time()
                flow_collection.insert_one(value)
            
            incident_collection = db[mongo_config["collection"]["incident"]]
            for key,value in graph_data["incident"].items():
                value["_key"] = key
                value["timestamp"] = time.time()
                incident_collection.insert_one(value)
            
            incident_metadata_collection = db[mongo_config["collection"]["incident_metadata"]]
            for key,value in graph_data["incident_metadata"].items():
                value["_key"] = key
                value["timestamp"] = time.time()
                incident_metadata_collection.insert_one(value)
            
            detector_collection = db[mongo_config["collection"]["detector"]]
            for key,value in graph_data["detector"].items():
                value["_key"] = key
                value["timestamp"] = time.time()
                detector_collection.insert_one(value)
            logging.info(f"Loaded graph database successfully")
    except Exception as e:
        logging.error("Unable to load graph database.")
        logging.error(traceback.format_exc())
        mongo_client = None
    return mongo_client

def get_cti_by_id(mongo_config: dict, credentials: dict, cti: RxomsCTI):
    """
    Function to get the CTI by ID from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            cti_collection = db[mongo_config["collection"]["cti"]]
            result = cti_collection.find_one({"_key": cti.id}, sort=[("timestamp", -1)])
            if result is not None:
                result_dict = dict(result)
                data = {cti.id: result_dict["mitigation"]}
                logging.debug(f"CTI data: {data}")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=data)
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="ID not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_cti_by_id: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_cti_by_id: {e}"
        )

def get_dt_by_mac(mongo_config: dict, credentials: dict, dt: RxomsDT):
    """
    Function to get the DT by MAC from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            dt_collection = db[mongo_config["collection"]["dt"]]
            mac = dt.mac
            result = dt_collection.find_one({"mac": mac}, sort=[("timestamp", -1)])
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                data = {key: result_dict}
                logging.debug(f"DT data: {data}")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=data)
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="MAC not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_dt_by_mac: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_dt_by_mac: {e}"
        )


def get_flow(mongo_config: dict, credentials: dict, flow: RxomsFlow):
    """
    Function to get the flow by eth_dst, in_port, switch from the graph data
    """
    try:
        eth_dst = flow.eth_dst
        in_port = flow.in_port
        switch = flow.switch
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            flow_collection = db[mongo_config["collection"]["flow"]]
            result = flow_collection.find_one(
                {
                    "eth_dst": eth_dst,
                    "in_port": int(in_port),
                    "switch": int(switch),
                },
                sort=[("timestamp", -1)],
            )
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                data = {key: result_dict}
                logging.debug(f"Flow data: {data}")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=data)
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="Flow not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_flow: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_flow: {e}"
        )


def get_incident_metadata(mongo_config: dict, credentials: dict, incident: RxomsCTI):
    """
    Function to get the incident metadata by incident_id from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            incident_metadata_collection = db[mongo_config["collection"]["incident_metadata"]]
            result = incident_metadata_collection.find_one(
                {"_key": incident.id}, sort=[("timestamp", -1)]
            )
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                data = {key: result_dict}
                logging.debug(f"Incident metadata: {data}")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=data)
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="Incident not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_incident_metadata: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED,
            error=f"Error in get_incident_metadata: {e}",
        )


def update_cti_by_id(mongo_config: dict, credentials: dict, cti: RxomsCTI):
    """
    Function to update the CTI by ID in the graph data
    """
    try:
        cti_id = cti.id
        cti_mitigation = cti.mitigation
        if isinstance(cti_mitigation, str):
            cti_mitigation = [cti_mitigation]
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            cti_collection = db[mongo_config["collection"]["cti"]]
            data = {"_key": cti_id, "mitigation": cti_mitigation, "timestamp": time.time()}
            cti_collection.insert_one(data)
            return RxomsResponse(
                status=RxomsResponseStatus.SUCCESS, data={cti_id: cti_mitigation}
            )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in update_cti_by_id: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in update_cti_by_id: {e}"
        )


def update_asset_by_mac(mongo_config: dict, credentials: dict, data: RxomsDT):
    """
    Function to update the DT by MAC in the graph data
    """
    try:
        mac = data.mac
        ip = data.ip
        status = data.status
        dt_type = data.type
        last_update = data.last_update
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            dt_collection = db[mongo_config["collection"]["dt"]]
            result = dt_collection.find_one({"mac": mac}, sort=[("timestamp", -1)])
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                if ip is not None:
                    result_dict["ip"] = ip
                if status is not None:
                    result_dict["status"] = status
                if dt_type is not None:
                    result_dict["type"] = dt_type
                if last_update is not None:
                    result_dict["last_update"] = last_update
                else:
                    result_dict["last_update"] = time.time()
                result_dict.pop("_id")
                result_dict["timestamp"] = time.time()
                dt_collection.insert_one(result_dict)
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                return RxomsResponse(status=RxomsResponseStatus.FAILED, error="MAC not found")
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in update_asset_by_mac: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED,
            error=f"Error in update_asset_by_mac: {e}",
        )


def get_switch_by_id(mongo_config: dict, credentials: dict, switch: RxomsSwitch):
    """
    Function to get the switch by switch_id from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            dt_collection = db[mongo_config["collection"]["dt"]]
            switch_id = switch.id
            result = dt_collection.find_one({"id": switch_id, "type": RxomsDTType.SWITCH}, sort=[("timestamp", -1)])
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="Switch not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_switch_by_id: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_switch_by_id: {e}"
        )


def update_switch(mongo_config: dict, credentials: dict, data: RxomsSwitch):
    """
    Function to update the switch in the graph data
    """
    
    try:
        mac = data.mac
        last_update = data.last_update
        max_byte = data.max_byte
        max_packet = data.max_packet
        port = data.port
        status = data.status
        sum_byte = data.sum_byte
        sum_packet = data.sum_packet
        switch_type = data.type
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            dt_collection = db[mongo_config["collection"]["dt"]]
            result = dt_collection.find_one({"mac": mac}, sort=[("timestamp", -1)])
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                if last_update is not None:
                    result_dict["last_update"] = last_update
                else:
                    result_dict["last_update"] = time.time()
                if max_byte is not None:
                    result_dict["max_byte"] = max_byte
                if max_packet is not None:
                    result_dict["max_packet"] = max_packet
                if port is not None:
                    result_dict["port"] = port
                if status is not None:
                    result_dict["status"] = status
                if sum_byte is not None:
                    result_dict["sum_byte"] = sum_byte
                if sum_packet is not None:
                    result_dict["sum_packet"] = sum_packet
                if switch_type is not None:
                    result_dict["type"] = switch_type
                result_dict.pop("_id")
                result_dict["timestamp"] = time.time()
                dt_collection.insert_one(result_dict)
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                return RxomsResponse(status=RxomsResponseStatus.FAILED, error="Switch not found")
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in update_switch: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in update_switch: {e}"
        )


def update_flow(mongo_config: dict, credentials: dict, data: RxomsFlow):
    """
    Function to update the flow in the graph data
    """
    
    try:
        eth_dst = data.eth_dst
        in_port = data.in_port
        switch = data.switch
        last_update = data.last_update
        mean_byte_count = data.mean_byte_count
        mean_packet_count = data.mean_packet_count
        recent_byte_value = data.recent_byte_value
        recent_packet_value = data.recent_packet_value
        status = data.status
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            flow_collection = db[mongo_config["collection"]["flow"]]
            result = flow_collection.find_one(
                {
                    "eth_dst": eth_dst,
                    "in_port": int(in_port),
                    "switch": int(switch),
                },
                sort=[("timestamp", -1)],
            )
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                if last_update is not None:
                    result_dict["last_update"] = last_update
                else:
                    result_dict["last_update"] = time.time()
                if mean_byte_count is not None:
                    result_dict["mean_byte_count"] = mean_byte_count
                if mean_packet_count is not None:
                    result_dict["mean_packet_count"] = mean_packet_count
                if recent_byte_value is not None:
                    result_dict["recent_byte_value"] = recent_byte_value
                if recent_packet_value is not None:
                    result_dict["recent_packet_value"] = recent_packet_value
                if status is not None:
                    result_dict["status"] = status
                result_dict.pop("_id")
                result_dict["timestamp"] = time.time()
                flow_collection.insert_one(result_dict)
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                return RxomsResponse(status=RxomsResponseStatus.FAILED, error="Flow not found")
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in update_flow: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in update_flow: {e}"
        )


def trace_root_cause_by_flow(mongo_config: dict, credentials: dict, flow: RxomsFlow):
    """
    Function to trace the root cause of an incident
    """
    try:
        if credentials is not None and mongo_config is not None:
            graph = get_graph_from_db(mongo_config, credentials).data
            dt_mac = None
            if flow.switch is not None and flow.in_port is not None:
                switch_id = flow.switch
                in_port = flow.in_port
                for _dt_key, dt_data in graph["digital_twin"].items():
                    if dt_data["type"] == RxomsDTType.SWITCH and str(dt_data["id"]) == str(
                        switch_id
                    ):
                        dt_mac = dt_data["port"][str(in_port)]
                        break
                if dt_mac is not None:
                    for dt, dt_data in graph["digital_twin"].items():
                        if dt_data["mac"] == dt_mac:
                            return RxomsResponse(
                                status=RxomsResponseStatus.SUCCESS, data={dt: dt_data}
                            )
                else:
                    return RxomsResponse(status=RxomsResponseStatus.ROOT_CAUSE_NOT_FOUND)
            else:
                return RxomsResponse(status=RxomsResponseStatus.FLOW_NOT_FOUND)
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in trace_root_cause_by_flow: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED,
            error=f"Error in trace_root_cause_by_flow: {e}",
        )


def trace_root_cause_by_switch(mongo_config: dict, credentials: dict, switch: RxomsSwitch):
    """
    Function to trace the root cause of an incident
    """
    try:
        if credentials is not None and mongo_config is not None:
            graph = get_graph_from_db(mongo_config, credentials).data
            switch_id = ""
            switch_mac = switch.mac
            for _dt_key, dt_data in graph["digital_twin"].items():
                if dt_data["mac"] == switch_mac:
                    switch_id = dt_data["id"]
            result = []
            for flow_key, flow_data in graph["flow"].items():
                if str(flow_data["switch"]) == str(switch_id):
                    if flow_data["status"] == RxomsFlowStatus.OVER:
                        result.append({flow_key: flow_data})
            return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=result)
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in trace_root_cause_by_switch: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED,
            error=f"Error in trace_root_cause_by_switch: {e}",
        )


def trace_consequence_by_switch(mongo_config: dict, credentials: dict, switch: RxomsSwitch):
    """
    Function to trace the root cause of an incident
    """
    try:
        if credentials is not None and mongo_config is not None:
            graph = get_graph_from_db(mongo_config, credentials).data
            switch_id = ""
            switch_mac = switch.mac
            for _dt_key, dt_data in graph["digital_twin"].items():
                if dt_data["mac"] == switch_mac:
                    switch_id = dt_data["id"]
            result = []
            for flow_key, flow_data in graph["flow"].items():
                if str(flow_data["switch"]) == str(switch_id):
                    if flow_data["status"] == RxomsFlowStatus.UNDER:
                        result.append({flow_key: flow_data})
            return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=result)
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in trace_consequence_by_switch: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED,
            error=f"Error in trace_consequence_by_switch: {e}",
        )


def get_detector(mongo_config: dict, credentials: dict, detector: RxomsDetector):
    """
    Function to get the detector by detector_id from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            detector_collection = db[mongo_config["collection"]["detector"]]
            result = detector_collection.find_one(
                {"_key": detector.id}, sort=[("timestamp", -1)]
            )
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                return RxomsResponse(
                    status=RxomsResponseStatus.FAILED, error="Detector not found"
                )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_detector: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_detector: {e}"
        )


def get_incident(mongo_config: dict, credentials: dict, dt: RxomsDT):
    """
    Function to get the incident by incident_id from the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            incident_collection = db[mongo_config["collection"]["incident"]]
            target_mac = dt.mac
            result = incident_collection.find_one(
                {"_key": target_mac}, sort=[("timestamp", -1)]
            )
            if result is not None:
                result_dict = dict(result)
                key = result_dict["_key"]
                result_dict.pop("_id")
                result_dict.pop("_key")
                result_dict.pop("timestamp")
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data={key: result_dict})
            else:
                result = {target_mac: {}}
                return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=result, error="Incident not found")
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_incident: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_incident: {e}"
        )


def update_incident(mongo_config: dict, credentials: dict, report: RxomsLogicalReport):
    """
    Function to update the incident by incident_id in the graph data
    """
    try:
        if credentials is not None and mongo_config is not None:
            target_mac, target_name = get_data_from_response(
                report.incident_consequence.target_dt
            )
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            incident_collection = db[mongo_config["collection"]["incident"]]
            data = report.__to_dict__()
            data["_key"] = target_mac
            data["timestamp"] = time.time()
            incident_collection.insert_one(data)
            data.pop("_id")
            data.pop("_key")
            data.pop("timestamp")
            return RxomsResponse(
                status=RxomsResponseStatus.SUCCESS,
                data={target_mac: data},
            )
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in update_incident: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in update_incident: {e}"
        )


def get_graph_from_db(mongo_config: dict, credentials: dict):
    """
    Function to get the graph data from the database
    """
    try:
        graph_data = {}
        graph_data["cti"] = {}
        graph_data["digital_twin"] = {}
        graph_data["flow"] = {}
        graph_data["incident"] = {}
        graph_data["incident_metadata"] = {}
        graph_data["detector"] = {}
        if credentials is not None and mongo_config is not None:
            db_username = credentials["username"]
            db_password = credentials["password"]
            db_uri = credentials["uri"]
            uri = f"mongodb://{db_username}:{db_password}@{db_uri}"
            mongo_client = pymongo.MongoClient(uri, server_api=ServerApi('1'))
            db = mongo_client[mongo_config["db"]]
            cti_collection = db[mongo_config["collection"]["cti"]]
            pipeline = [
                {"$sort": {"timestamp": -1}},
                {
                    "$group": {
                        "_id": "$_key",
                        "latest_item": {"$first": "$$ROOT"} 
                    }
                },
                {"$replaceRoot": {"newRoot": "$latest_item"}}
            ]
            cti_data = cti_collection.aggregate(pipeline)
            for cti in cti_data:
                key = cti["_key"]
                data = cti["mitigation"]
                graph_data["cti"][key] = data

            dt_collection = db[mongo_config["collection"]["dt"]]
            dt_data = dt_collection.aggregate(pipeline)
            for dt in dt_data:
                key = dt["_key"]
                dt.pop("_id")
                dt.pop("_key")
                dt.pop("timestamp")
                graph_data["digital_twin"][key] = dt
            flow_collection = db[mongo_config["collection"]["flow"]]
            flow_data = flow_collection.aggregate(pipeline)
            for flow in flow_data:
                key = flow["_key"]
                flow.pop("_id")
                flow.pop("_key")
                flow.pop("timestamp")
                graph_data["flow"][key] = flow
            incident_collection = db[mongo_config["collection"]["incident"]]
            incident_data = incident_collection.aggregate(pipeline)
            for incident in incident_data:
                key = incident["_key"]
                incident.pop("_id")
                incident.pop("_key")
                incident.pop("timestamp")
                graph_data["incident"][key] = incident
            incident_metadata_collection = db[mongo_config["collection"]["incident_metadata"]]
            incident_metadata_data = incident_metadata_collection.aggregate(pipeline)
            for incident_metadata in incident_metadata_data:
                key = incident_metadata["_key"]
                incident_metadata.pop("_id")
                incident_metadata.pop("_key")
                incident_metadata.pop("timestamp")
                graph_data["incident_metadata"][key] = incident_metadata
            detector_collection = db[mongo_config["collection"]["detector"]]
            detector_data = detector_collection.aggregate(pipeline)
            for detector in detector_data:
                key = detector["_key"]
                detector.pop("_id")
                detector.pop("_key")
                detector.pop("timestamp")
                graph_data["detector"][key] = detector
            return RxomsResponse(status=RxomsResponseStatus.SUCCESS, data=graph_data)
  
        else:
            return RxomsResponse(
                status=RxomsResponseStatus.FAILED, error="Credentials not found"
            )
    except Exception as e:
        logging.error(f"Error in get_graph: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in get_graph: {e}"
        )