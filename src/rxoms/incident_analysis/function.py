import logging
import time
import traceback
import uuid

import requests
import yaml

from rxoms.base_model import (
    RxomsAnomalValue,
    RxomsDT,
    RxomsDTStatus,
    RxomsDTType,
    RxomsFlowStatus,
    RxomsIncident,
    RxomsIncidentCause,
    RxomsIncidentConsequence,
    RxomsIncidentPattern,
    RxomsIncidentTime,
    RxomsIncidentType,
    RxomsKnowledgeGraphResource,
    RxomsLimit,
    RxomsLogicalReport,
    RxomsPhysicalReport,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsStorage,
)
from rxoms.utils.rxoms_utils import get_data_from_response

DEFUALT_INCIDENT = "T1498"
logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


def get_incident_info(url: str, incident_target: RxomsDT):
    try:
        incident_response = requests.post(
            str(url) + RxomsKnowledgeGraphResource.GET_INCIDENT,
            json=incident_target.__to_dict__(),
        )
        response_dict = incident_response.json()
        logging.debug(f"Get incident response: {response_dict}")
        incident_dict = response_dict["data"]
        incident_id, incident_data = get_data_from_response(incident_dict)
        return incident_data
    except Exception as e:
        logging.error(f"Error when get_incident_info: {e}")
        logging.error(traceback.format_exc())
    return DEFUALT_INCIDENT


def trace_by_flow(
    url: str,
    anomaly_flow_dict: dict,
    dts_cause: dict,
    checked_swicht: list,
    traced_flow: list,
):
    try:
        if anomaly_flow_dict["status"] == RxomsFlowStatus.OVER:
            traced_flow.append(anomaly_flow_dict["id"])
            dt_response = requests.post(
                str(url) + RxomsKnowledgeGraphResource.TRACE_ROOT_CAUSE_BY_FLOW,
                json=anomaly_flow_dict,
            )
            response_dict = dt_response.json()
            if response_dict["status"] == RxomsResponseStatus.SUCCESS:
                if "data" in response_dict:
                    dt_data_dict = response_dict["data"]
                    dt_id, dt_data = get_data_from_response(dt_data_dict)
                    if str(dt_data["type"]) == RxomsDTType.ASSET.value:
                        dts_cause[dt_id] = dt_data
                    elif str(dt_data["type"]) == RxomsDTType.SWITCH.value:
                        switch_request_dict = {"mac": dt_data["mac"]}
                        if dt_data["mac"] not in checked_swicht:
                            checked_swicht.append(dt_data["mac"])
                            switch_response = requests.post(
                                str(url)
                                + RxomsKnowledgeGraphResource.TRACE_ROOT_CAUSE_BY_SWITCH,
                                json=switch_request_dict,
                            )
                            flow_list = switch_response.json()["data"]
                            for flow_dict in flow_list:
                                flow_key, flow_data = get_data_from_response(flow_dict)
                                flow_data["id"] = flow_key
                                trace_by_flow(
                                    url,
                                    flow_data,
                                    dts_cause,
                                    checked_swicht,
                                    traced_flow,
                                )
    except Exception as e:
        logging.error(f"Error when trace_by_flow: {e}")
        logging.error(traceback.format_exc())
    return None, None


def analyse_incident(
    url: str,
    report: RxomsPhysicalReport,
    data_path: str,
    log_physical_report: bool = False,
) -> RxomsResponse:
    try:
        # Update anomaly flow
        incident_type = None  ######
        incident_metadata = None  ######
        logical_report = None
        anomaly_flow_dict = report.anomaly.anomaly_flow.__to_dict__()
        logging.debug(f"Anomaly flow: {anomaly_flow_dict}")
        common_metric = report.anomaly.common_metric
        logging.debug(f"Common metric: {common_metric}")
        anomaly_result = report.anomaly.anomaly_result
        logging.debug(f"Anomaly result : {anomaly_result}")
        if int(anomaly_result["byte_anomaly"]) == int(RxomsAnomalValue.ABNORMAL):
            if int(common_metric["byte_count"]) >= int(
                anomaly_flow_dict["mean_byte_count"]
            ):
                anomaly_flow_dict["status"] = RxomsFlowStatus.OVER
                incident_type = RxomsIncidentType.DDOS.value
            else:
                anomaly_flow_dict["status"] = RxomsFlowStatus.UNDER
            if log_physical_report:
                p_file_path = (
                    str(data_path + RxomsStorage.PHYSICAL.value) + f"/{report.id}.yaml"
                )
                with open(p_file_path, "w") as yaml_file:
                    yaml.dump(
                        report.__to_dict__(),
                        yaml_file,
                        default_flow_style=False,
                        indent=4,
                    )
        anomaly_flow_dict["recent_byte_value"] = common_metric["byte_count"]
        anomaly_flow_dict["recent_packet_value"] = common_metric["packet_count"]
        anomaly_flow_dict["last_update"] = time.time()
        update_flow_response = requests.post(
            str(url) + RxomsKnowledgeGraphResource.UPDATE_FLOW, json=anomaly_flow_dict
        )
        logging.debug(f"Update flow response: {update_flow_response.json()}")

        if incident_type is not None:
            # Analyse incident
            # Get Incident information
            incident_target = report.physical_entity
            incident = get_incident_info(url, incident_target)
            logical_report = RxomsLogicalReport.model_validate(incident)
            logging.debug(f"Logical report: {logical_report}")
            # Remove solve incident
            list_remove = []

            if logical_report.incident is not None:
                for key, incident in logical_report.incident.items():
                    incident_last_update = incident["last_update"]
                    if (
                        int(time.time()) - int(incident_last_update)
                        > RxomsLimit.INCIDENT_TIMEOUT
                    ):
                        list_remove.append(key)
            else:
                logical_report.incident = {}
            for key in list_remove:
                logical_report.incident.pop(key)
            if len(logical_report.incident.keys()) == 0 or logical_report.id is None:
                logical_report.id = str(uuid.uuid4())
            # Trace root cause
            dts_cause = {}
            checked_swicht = []
            switch_response = requests.post(
                str(url) + RxomsKnowledgeGraphResource.GET_SWITCH_BY_ID,
                json={"id": anomaly_flow_dict["switch"]},
            )
            switch_data_dict = switch_response.json()
            if "data" in switch_data_dict:
                switch_key, switch_data = get_data_from_response(
                    switch_data_dict["data"]
                )
                checked_swicht.append(switch_data["mac"])
            traced_flow = []
            trace_by_flow(
                url, anomaly_flow_dict, dts_cause, checked_swicht, traced_flow
            )
            list_dts_cause = {}
            logging.debug(f"List of Switch: {checked_swicht}")
            for _dt_id, dt_data in dts_cause.items():
                list_dts_cause[dt_data["mac"]] = dt_data["name"]
                dt_data["status"] = RxomsDTStatus.ATTACK.value
                dt_data["last_update"] = time.time()
                update_dt_response = requests.post(
                    str(url) + RxomsKnowledgeGraphResource.UPDATE_ASSET_BY_MAC,
                    json=dt_data,
                )
            # Update incident cause
            if logical_report.incident_cause is None:
                logical_report.incident_cause = RxomsIncidentCause(
                    root_cause=list_dts_cause
                )  ########
            else:
                for key, dt in list_dts_cause.items():
                    logical_report.incident_cause.root_cause[key] = dt

            # Get Incident metadata

            incident_metadata_respone = requests.post(
                str(url) + RxomsKnowledgeGraphResource.GET_INCIDENT_METADATA,
                json={"id": incident_type},
            )
            incident_metadata_dict = incident_metadata_respone.json()
            if "data" in incident_metadata_dict:
                incident_key, incident_metadata = get_data_from_response(
                    incident_metadata_dict["data"]
                )
            for key, incident in logical_report.incident.items():
                logical_report.incident[key] = RxomsIncident.model_validate(incident)

            if incident_type in logical_report.incident:
                incident = logical_report.incident[incident_type]
                incident.metrics.append(report.id)
                incident.last_update = time.time()
                if incident_metadata is not None:
                    incident.incident_metadata = incident_metadata
                for flow in traced_flow:
                    if flow not in incident.runtime_pattern.pattern:
                        incident.runtime_pattern.pattern.append(flow)
                incident.runtime_pattern.incident_time.duration = (
                    time.time() - incident.runtime_pattern.incident_time.start_time
                )
            else:
                incident = RxomsIncident(
                    incident_type=incident_type,
                    incident_metadata=incident_metadata,
                    metrics=[report.id],
                    last_update=time.time(),
                    runtime_pattern=RxomsIncidentPattern(
                        pattern=traced_flow,
                        incident_time=RxomsIncidentTime(
                            start_time=time.time(), duration=0
                        ),
                    ),
                    id=str(uuid.uuid4()),
                )
                logical_report.incident[incident_type] = incident

            affected_dt_dict = {}
            for switch_mac in checked_swicht:
                logging.debug(f"Switch mac: {switch_mac}")
                switch_request_dict = {"mac": switch_mac}
                switch_response = requests.post(
                    str(url) + RxomsKnowledgeGraphResource.TRACE_CONSEQUENCE_BY_SWITCH,
                    json=switch_request_dict,
                )
                switch_data_dict = switch_response.json()
                logging.debug(f"Switch trace data dict: {switch_data_dict}")
                if "data" in switch_data_dict:
                    flow_list = switch_data_dict["data"]
                    logging.debug(f"Flow list: {flow_list}")
                    for flow_dict in flow_list:
                        flow_key, flow_data = get_data_from_response(flow_dict)
                        dt_response = requests.post(
                            str(url)
                            + RxomsKnowledgeGraphResource.TRACE_ROOT_CAUSE_BY_FLOW,
                            json=flow_data,
                        )
                        dt_data_dict = dt_response.json()
                        logging.debug(f"DT data dict: {dt_data_dict}")
                        if "data" in dt_data_dict:
                            dt_key, dt_data = get_data_from_response(
                                dt_data_dict["data"]
                            )
                            affected_dt_dict[dt_data["mac"]] = dt_data["name"]
                            dt_data["status"] = RxomsDTStatus.AFFECTED.value
                            dt_data["last_update"] = time.time()
                            logging.debug(f"DT data: {dt_data}")
                            if str(dt_data["type"]) == RxomsDTType.SWITCH.value:
                                update_dt_response = requests.post(
                                    str(url)
                                    + RxomsKnowledgeGraphResource.UPDATE_SWITCH,
                                    json=dt_data,
                                )
                            else:
                                update_dt_response = requests.post(
                                    str(url)
                                    + RxomsKnowledgeGraphResource.UPDATE_ASSET_BY_MAC,
                                    json=dt_data,
                                )
                            logging.debug(
                                f"Update DT response: {update_dt_response.json()}"
                            )

            if logical_report.incident_consequence is None:
                logical_report.incident_consequence = RxomsIncidentConsequence(
                    target_dt={incident_target.mac: incident_target.name},
                    affected_dt=affected_dt_dict,
                )
            else:
                logical_report.incident_consequence.affected_dt.update(affected_dt_dict)

            logical_report_request = logical_report.__to_dict__()
            logicall_report_response = requests.post(
                str(url) + RxomsKnowledgeGraphResource.UPDATE_INCIDENT,
                json=logical_report_request,
            )
            logging.debug(
                f"Logical incident response: {logicall_report_response.json()}"
            )
            l_file_path = (
                str(data_path + RxomsStorage.LOGICAL.value)
                + f"/{logical_report.id}.yaml"
            )
            with open(l_file_path, "w") as yaml_file:
                yaml.dump(
                    logical_report_request,
                    yaml_file,
                    default_flow_style=False,
                    indent=4,
                )
        return logical_report
    except Exception as e:
        logging.error(f"Error when analyse_incident: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(status=RxomsResponseStatus.FAILED)
