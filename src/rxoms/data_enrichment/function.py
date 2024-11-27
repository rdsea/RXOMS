import logging
import time
import traceback
import uuid

import requests

from rxoms.base_model import (
    RxomsAnomaly,
    RxomsDetector,
    RxomsDT,
    RxomsIncidentAnalysisResource,
    RxomsKnowledgeGraphResource,
    RxomsMonitor,
    RxomsPhysicalReport,
    RxomsResponse,
    RxomsResponseStatus,
)
from rxoms.utils.rxoms_utils import get_data_from_response

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)


def enrich_anomaly_report(ulr: str, request: RxomsResponse) -> RxomsPhysicalReport:
    try:
        # Buil physical report - anomaly report

        report_time = time.time()
        report_id = str(uuid.uuid4())
        detection_time = time.time()
        monitoring_time = request.runtime

        # Get flow information
        flow_request_dict = {
            "switch": request.switch,
            "in_port": request.in_port,
            "eth_dst": request.eth_dst,
        }
        flow_response = requests.post(
            str(ulr) + RxomsKnowledgeGraphResource.GET_FLOW, json=flow_request_dict
        )
        response_dict = flow_response.json()
        flow_dict = response_dict["data"]
        flow_id, flow_data = get_data_from_response(flow_dict)
        flow_data["id"] = flow_id

        # Get detector information
        detector_id = flow_data["detector"]
        detector_request_dict = {"id": detector_id}
        detector_response = requests.post(
            str(ulr) + RxomsKnowledgeGraphResource.GET_DETECTOR,
            json=detector_request_dict,
        )
        detector_dict = detector_response.json()["data"]
        detector_id, detector_data = get_data_from_response(detector_dict)

        # Get attack target information
        target_mac = request.eth_dst
        dt_request_dict = {"mac": target_mac}
        dt_response = requests.post(
            str(ulr) + RxomsKnowledgeGraphResource.GET_DT_BY_MAC, json=dt_request_dict
        )
        dt_dict = dt_response.json()["data"]
        dt_id, dt_data = get_data_from_response(dt_dict)

        # Build Monitoring report
        monitor_report = RxomsMonitor(
            user_id=request.user_id,
            instance_id=request.instance_id,
            functionality=request.functionality,
            stage_id=request.stage_id,
            application_name=request.application_name,
            role=request.role,
            monitoring_time=monitoring_time,
        )
        # Build Detector Report
        detector_report = RxomsDetector(
            detector_name=detector_data["detector_name"],
            id=detector_id,
            ml_algorithm=detector_data["ml_algorithm"],
            last_update=detector_data["metadata"]["last_train"],
            detection_time=detection_time,
            configuration=detector_data["configuration"],
            performance=detector_data["performance"],
        )
        # Build Anomaly Report
        common_metric = {
            "byte_count": request.byte_count,
            "packet_count": request.packet_count,
        }
        ml_metric = {
            "byte_scores": request.byte_scores,
            "packet_scores": request.packet_scores,
        }
        anomaly_result = {
            "byte_anomaly": request.byte_anomaly,
            "packet_anomaly": request.packet_anomaly,
        }
        anomaly_report = RxomsAnomaly(
            common_metric=common_metric,
            ml_metric=ml_metric,
            anomaly_result=anomaly_result,
            anomaly_flow=flow_data,
        )

        # Build DT Report
        dt_report = RxomsDT(
            id=dt_id,
            mac=dt_data["mac"],
            ip=dt_data["ip"],
            status=dt_data["status"],
            type=dt_data["type"],
            last_update=dt_data["last_update"],
            name=dt_data["name"],
        )

        # Build Physical Report
        physical_report = RxomsPhysicalReport(
            id=report_id,
            report_time=report_time,
            monitor=monitor_report,
            detector=detector_report,
            anomaly=anomaly_report,
            physical_entity=dt_report,
        )
        logging.info(f"Physical report: {physical_report.__to_dict__()}")
        return physical_report

    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(traceback.format_exc())
        return RxomsResponse(
            status=RxomsResponseStatus.FAILED, error=f"Error in anomaly_report: {e}"
        )


def send_physical_report(url: str, physical_report: RxomsPhysicalReport):
    try:
        url_ = str(url) + RxomsIncidentAnalysisResource.INCIDENT_REPORT
        logging.debug(f"Sending physical report to {url_}")
        response = requests.post(
            str(url) + RxomsIncidentAnalysisResource.INCIDENT_REPORT,
            json=physical_report.__to_dict__(),
        )
        response_dict = response.json()
        # logging.debug(f"Response from incident analysis: {response_dict}")
        return response_dict
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(traceback.format_exc())
        return None
