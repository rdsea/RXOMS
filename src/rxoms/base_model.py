from enum import Enum
from typing import Optional

from pydantic import BaseModel


class RxomsCTI(BaseModel):
    """
    Cyber Threat Intelligence Attributes: 
    - id: type string, unique identifier of CTI define by MITRE ATT&CK
    - mitigation: type list of string | list of mitigation technique to prevent the attack, the ID of the mitigation technique is defined by MITRE ATT&CK
    """
    id: str
    mitigation: Optional[list] | Optional[str] = None

    def __to_dict__(self):
        result = {}
        if self.id is not None:
            result["id"] = self.id
        if self.mitigation is not None:
            result["mitigation"] = self.mitigation
        return result


class RxomsDT(BaseModel):
    """
    Digital Twin Attributes:
    - mac: type string, unique identifier of DT
    - id: type string | int | float, unique identifier of DT
    - ip: type string, IP address of DT
    - status: type string, status of DT (normal, attack, affected)
    - type: type string, type of DT (switch, asset, gateway)
    - last_update: type string | int | float, last update time of DT
    - name: type string | int | float, name of DT
    - norm_value: type float | int, normalized value in DT
    """
    mac: Optional[str] = None
    id: Optional[str] | Optional[int] | Optional[float] = None
    ip: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None
    last_update: Optional[str] | Optional[int] | Optional[float] = None
    name: Optional[str] | Optional[int] | Optional[float] = None
    norm_value: Optional[float] | Optional[int] = None

    def __to_dict__(self):
        result = {}
        if self.mac is not None:
            result["mac"] = self.mac
        if self.id is not None:
            result["id"] = self.id
        if self.ip is not None:
            result["ip"] = self.ip
        if self.status is not None:
            result["status"] = self.status
        if self.type is not None:
            result["type"] = self.type
        if self.last_update is not None:
            result["last_update"] = self.last_update
        if self.name is not None:
            result["name"] = self.name
        if self.norm_value is not None:
            result["norm_value"] = self.norm_value
        return result


class RxomsFlow(BaseModel):
    """
    Network Flow Attributes:
    - eth_dst: type string, destination MAC address of flow
    - in_port: type string | int, input port of flow
    - switch: type string | int, switch ID of flow
    - id: type string, unique identifier of flow
    - last_update: type string | int | float, last update time of flow
    - mean_byte_count: type float, mean byte count of flow
    - mean_packet_count: type float, mean packet count of flow
    - recent_byte_value: type int, recent byte value of flow
    - recent_packet_value: type int, recent packet value of flow
    - status: type string, status of flow (overflow, underflow)
    """
    eth_dst: str
    in_port: int | str
    switch: int | str
    id: Optional[str] = None
    last_update: Optional[str] | Optional[int] | Optional[float] = None
    mean_byte_count: Optional[float] = None
    mean_packet_count: Optional[float] = None
    recent_byte_value: Optional[int] = None
    recent_packet_value: Optional[int] = None
    status: Optional[str] = None

    def __to_dict__(self):
        result = {}
        if self.eth_dst is not None:
            result["eth_dst"] = self.eth_dst
        if self.in_port is not None:
            result["in_port"] = self.in_port
        if self.switch is not None:
            result["switch"] = self.switch
        if self.id is not None:
            result["id"] = self.id
        if self.last_update is not None:
            result["last_update"] = self.last_update
        if self.mean_byte_count is not None:
            result["mean_byte_count"] = self.mean_byte_count
        if self.mean_packet_count is not None:
            result["mean_packet_count"] = self.mean_packet_count
        if self.recent_byte_value is not None:
            result["recent_byte_value"] = self.recent_byte_value
        if self.recent_packet_value is not None:
            result["recent_packet_value"] = self.recent_packet_value
        if self.status is not None:
            result["status"] = self.status
        return result


class RxomsSwitch(RxomsDT):
    """
    Switch Attributes:
    - inherit from RxomsDT
    - max_byte: type int | float | string, maximum byte of switch
    - max_packet: type int | float | string, maximum packet of switch
    - port: type dict, connection on ports of switch
    - sum_byte: type int | float | string, sum byte of switch
    - sum_packet: type int | float | string, sum packet of switch
    """
    max_byte: Optional[int] | Optional[float] | Optional[str] = None
    max_packet: Optional[int] | Optional[float] | Optional[str] = None
    port: Optional[dict] = None
    sum_byte: Optional[int] | Optional[float] | Optional[str] = None
    sum_packet: Optional[int] | Optional[float] | Optional[str] = None

    def __to_dict__(self):
        result = super().__to_dict__()
        if self.max_byte is not None:
            result["max_byte"] = self.max_byte
        if self.max_packet is not None:
            result["max_packet"] = self.max_packet
        if self.port is not None:
            result["port"] = self.port
        if self.sum_byte is not None:
            result["sum_byte"] = self.sum_byte
        if self.sum_packet is not None:
            result["sum_packet"] = self.sum_packet
        return result


class RxomsResponse(BaseModel):
    """
    Response Attributes:
    - status: type string, status of response (success, failed, ...)
    - data: type dict | list | string, data of response
    - error: type string, error message of response
    """
    status: str
    data: Optional[dict] | Optional[list] | Optional[str] = None
    error: Optional[str] = None

    def __to_dict__(self):
        result = {}
        if self.status is not None:
            result["status"] = self.status
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return result


class RxomsMonitor(BaseModel):
    """
    Monitor Attributes:
    - user_id: type string, user ID of monitor
    - instance_id: type string, ID of monitored instance
    - stage_id: type string, ID of monitored stage
    - functionality: type string, functionality of monitored instance
    - application_name: type string, name of monitored application
    - role: type string, role of monitored instance
    - monitoring_time: type string | int | float, monitoring time of monitor
    """
    user_id: Optional[str] = None
    instance_id: Optional[str] = None
    stage_id: Optional[str] = None
    functionality: Optional[str] = None
    application_name: Optional[str] = None
    role: Optional[str] = None
    monitoring_time: Optional[str] | Optional[int] | Optional[float] = None

    def __to_dict__(self):
        result = {}
        if self.user_id is not None:
            result["user_id"] = self.user_id
        if self.instance_id is not None:
            result["instance_id"] = self.instance_id
        if self.stage_id is not None:
            result["stage_id"] = self.stage_id
        if self.functionality is not None:
            result["functionality"] = self.functionality
        if self.application_name is not None:
            result["application_name"] = self.application_name
        if self.role is not None:
            result["role"] = self.role
        if self.monitoring_time is not None:
            result["monitoring_time"] = self.monitoring_time
        return result


class RxomsDetector(BaseModel):
    """
    Detector Attributes:
    - detector_name: type string, name of detector
    - id: type string, unique identifier of detector
    - ml_algorithm: type string, machine learning algorithm of detector
    - last_update: type string | int | float, last update time of detector
    - detection_time: type string | int | float, detection time of detector
    - configuration: type dict, current configuration of detector
    - detecting: type list, list of detecting instance
    - metadata: type dict, metadata of detector
    - performance: type dict, current performance of detector
    """
    detector_name: Optional[str] = None
    id: Optional[str] = None
    ml_algorithm: Optional[str] = None
    last_update: Optional[str] | Optional[int] | Optional[float] = None
    detection_time: Optional[str] | Optional[int] | Optional[float] = None
    configuration: Optional[dict] = None
    detecting: Optional[list] = None
    metadata: Optional[dict] = None
    performance: Optional[dict] = None

    def __to_dict__(self):
        result = {}
        if self.detector_name is not None:
            result["detector_name"] = self.detector_name
        if self.id is not None:
            result["id"] = self.id
        if self.ml_algorithm is not None:
            result["ml_algorithm"] = self.ml_algorithm
        if self.last_update is not None:
            result["last_update"] = self.last_update
        if self.detection_time is not None:
            result["detection_time"] = self.detection_time
        if self.configuration is not None:
            result["configuration"] = self.configuration
        if self.detecting is not None:
            result["detecting"] = self.detecting
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.performance is not None:
            result["performance"] = self.performance
        return result


class RxomsAnomaly(BaseModel):
    """
    Anomaly Attributes:
    - id: type string, unique identifier of anomaly
    - common_metric: type string | int | float | dict, common metric of anomaly
    - ml_metric: type string | int | float | dict, machine learning metric of anomaly
    - anomaly_result: type string | int | float | dict, result of anomaly
    """
    id: Optional[str] = None
    common_metric: Optional[str] | Optional[float] | Optional[int] | Optional[dict] = (
        None
    )
    ml_metric: Optional[str] | Optional[float] | Optional[int] | Optional[dict] = None
    anomaly_result: Optional[str] | Optional[float] | Optional[int] | Optional[dict] = (
        None
    )
    anomaly_flow: Optional[RxomsFlow] = None

    def __to_dict__(self):
        result = {}
        if self.id is not None:
            result["id"] = self.id
        if self.common_metric is not None:
            result["common_metric"] = self.common_metric
        if self.ml_metric is not None:
            result["ml_metric"] = self.ml_metric
        if self.anomaly_result is not None:
            result["anomaly_result"] = self.anomaly_result
        if self.anomaly_flow is not None:
            result["anomaly_flow"] = self.anomaly_flow.__to_dict__()
        return result


class RxomsProtector(BaseModel):
    """
    Protector Attributes:
    - tool_id: type string, unique identifier of protector
    - functionality: type string, functionality of protector
    - last_update: type string | int | float, last update time of protector
    """
    tool_id: Optional[str] = None
    functionality: Optional[str] = None
    last_update: Optional[str] | Optional[int] | Optional[float] = None

    def __to_dict__(self):
        result = {}
        if self.tool_id is not None:
            result["tool_id"] = self.tool_id
        if self.functionality is not None:
            result["functionality"] = self.functionality
        if self.last_update is not None:
            result["last_update"] = self.last_update
        return result


class RxomsPhysicalReport(BaseModel):
    """
    Anomaly Report Attributes (report at physical layer):
    - id: type string, unique identifier of report
    - detector: type RxomsDetector, detector of report
    - anomaly: type RxomsAnomaly, anomaly of report
    - monitor: type RxomsMonitor, monitor of report
    - physical_entity: type RxomsDT, physical entity of report
    - report_time: type string | int | float, report time of report
    """

    id: Optional[str] = None
    detector: Optional[RxomsDetector] = None
    anomaly: Optional[RxomsAnomaly] = None
    monitor: Optional[RxomsMonitor] = None
    physical_entity: Optional[RxomsDT] = None
    report_time: Optional[str] | Optional[int] | Optional[float] = None

    def __to_dict__(self):
        result = {}
        if self.id is not None:
            result["id"] = self.id
        if self.detector is not None:
            result["detector"] = self.detector.__to_dict__()
        if self.anomaly is not None:
            result["anomaly"] = self.anomaly.__to_dict__()
        if self.monitor is not None:
            result["monitor"] = self.monitor.__to_dict__()
        if self.physical_entity is not None:
            result["physical_entity"] = self.physical_entity.__to_dict__()
        if self.report_time is not None:
            result["report_time"] = self.report_time
        return result


class RxomsIncidentTime(BaseModel):
    """
    Incident Time Attributes:
    - start_time: type string | int | float, start time of incident
    - duration: type string | int | float, duration of incident
    """
    start_time: Optional[str] | Optional[int] | Optional[float] = None
    duration: Optional[str] | Optional[int] | Optional[float] = None

    def __to_dict__(self):
        result = {}
        if self.start_time is not None:
            result["start_time"] = self.start_time
        if self.duration is not None:
            result["duration"] = self.duration
        return result


class RxomsIncidentPattern(BaseModel):
    """
    Incident Pattern Attributes:
    - incident_time: type RxomsIncidentTime, incident time of pattern
    - pattern: type list of RxomsFlow, pattern of incident
    """
    incident_time: Optional[RxomsIncidentTime] = None
    pattern: Optional[list] = None  # list of RxomsFlow

    def __to_dict__(self):
        result = {}
        if self.incident_time is not None:
            result["incident_time"] = self.incident_time.__to_dict__()
        if self.pattern is not None:
            result["pattern"] = self.pattern
        return result


class RxomsIncident(BaseModel):
    """
    Incident Attributes:
    - incident_type: type string, type of incident
    - incident_metadata: type dict, metadata of incident
    - metrics: type list, list of RxomsPhysicalReport.id
    - runtime_pattern: type RxomsIncidentPattern, runtime pattern of incident
    - last_update: type string | int | float, last update time of incident
    - id: type string, unique identifier of incident
    """
    incident_type: Optional[str] = None
    incident_metadata: Optional[dict] = None
    metrics: Optional[list] = None  # list of RxomsPhysicalReport.id
    runtime_pattern: Optional[RxomsIncidentPattern] = None
    last_update: Optional[str] | Optional[int] | Optional[float] = None
    id: Optional[str] = None

    def __to_dict__(self):
        result = {}
        if self.incident_type is not None:
            result["incident_type"] = self.incident_type
        if self.incident_metadata is not None:
            result["incident_metadata"] = self.incident_metadata
        if self.metrics is not None:
            result["metrics"] = self.metrics
        if self.runtime_pattern is not None:
            result["runtime_pattern"] = self.runtime_pattern.__to_dict__()
        if self.last_update is not None:
            result["last_update"] = self.last_update
        if self.id is not None:
            result["id"] = self.id
        return result


class RxomsIncidentCause(BaseModel):
    """
    Incident Cause Attributes:
    - root_cause: type dict, root cause of incident
    """
    root_cause: Optional[dict] = None  #

    def __to_dict__(self):
        result = {}
        if self.root_cause is not None:
            result["root_cause"] = self.root_cause
        return result


class RxomsIncidentConsequence(BaseModel):
    """
    Incident Consequence Attributes:
    - target_dt: type dict, target DT of incident
    - affected_dt: type dict, affected DT of incident
    """
    target_dt: Optional[dict] = None
    affected_dt: Optional[dict] = None  # list of RxomsDT.mac

    def __to_dict__(self):
        result = {}
        if self.target_dt is not None:
            result["target_dt"] = self.target_dt
        if self.affected_dt is not None:
            result["affected_dt"] = self.affected_dt
        return result


class RxomsLogicalReport(BaseModel):
    """
    Incident Report Attributes (report at logical layer):
    - incident: type dict of RxomsIncident
    - incident_cause: type RxomsIncidentCause, incident cause of report
    - incident_consequence: type RxomsIncidentConsequence, incident consequence of report
    - id: type string, unique identifier of report
    """

    incident: Optional[dict] = None  # dict of RxomsIncident
    incident_cause: Optional[RxomsIncidentCause] = None
    incident_consequence: Optional[RxomsIncidentConsequence] = None
    id: Optional[str] = None

    def __to_dict__(self):
        result = {}
        if self.incident is not None:
            result["incident"] = {}
            for key, value in self.incident.items():
                if isinstance(value, RxomsIncident):
                    result["incident"][key] = value.__to_dict__()
                else:
                    result["incident"][key] = value
        if self.incident_cause is not None:
            result["incident_cause"] = self.incident_cause.__to_dict__()
        if self.incident_consequence is not None:
            result["incident_consequence"] = self.incident_consequence.__to_dict__()
        if self.id is not None:
            result["id"] = self.id
        return result


class RxomsSecurityPlan(BaseModel):
    """
    Security Plan Attributes:
    - plan: type dict, plan of security
    """
    plan: Optional[dict] = None  # Todo: define plan structure

    def __to_dict__(self):
        result = {}
        if self.plan is not None:
            result["plan"] = self.plan
        return result


class RxomsSinditReport(BaseModel):
    """Specific to Sindit application. Other applications may have different report structure"""

    in_port: Optional[str] | Optional[int] | Optional[float] = None
    eth_dst: Optional[str] | Optional[int] | Optional[float] = None
    out_port: Optional[str] | Optional[int] | Optional[float] = None
    packet_count: Optional[str] | Optional[int] | Optional[float] = None
    byte_count: Optional[str] | Optional[int] | Optional[float] = None
    switch: Optional[str] | Optional[int] | Optional[float] = None
    user_id: Optional[str] | Optional[int] | Optional[float] = None
    instance_id: Optional[str] | Optional[int] | Optional[float] = None
    stage_id: Optional[str] | Optional[int] | Optional[float] = None
    functionality: Optional[str] | Optional[int] | Optional[float] = None
    application_name: Optional[str] | Optional[int] | Optional[float] = None
    role: Optional[str] | Optional[int] | Optional[float] = None
    timestamp: Optional[str] | Optional[int] | Optional[float] = None
    run_id: Optional[str] | Optional[int] | Optional[float] = None
    runtime: Optional[str] | Optional[int] | Optional[float] = None
    packet_count_shifted: Optional[int] | Optional[float] = None
    byte_count_shifted: Optional[int] | Optional[float] = None
    packet_count_average: Optional[int] | Optional[float] = None
    byte_count_average: Optional[int] | Optional[float] = None
    byte_count_average_norm: Optional[int] | Optional[float] = None
    packet_count_average_norm: Optional[int] | Optional[float] = None
    byte_scores: Optional[int] | Optional[float] = None
    packet_scores: Optional[int] | Optional[float] = None
    byte_anomaly: Optional[str] | Optional[float] | Optional[int] = None
    packet_anomaly: Optional[str] | Optional[float] | Optional[int] = None

    def __to_dict__(self):
        result = {}
        if self.in_port is not None:
            result["in_port"] = self.in_port
        if self.eth_dst is not None:
            result["eth_dst"] = self.eth_dst
        if self.out_port is not None:
            result["out_port"] = self.out_port
        if self.packet_count is not None:
            result["packet_count"] = self.packet_count
        if self.byte_count is not None:
            result["byte_count"] = self.byte_count
        if self.switch is not None:
            result["switch"] = self.switch
        if self.user_id is not None:
            result["user_id"] = self.user_id
        if self.instance_id is not None:
            result["instance_id"] = self.instance_id
        if self.stage_id is not None:
            result["stage_id"] = self.stage_id
        if self.functionality is not None:
            result["functionality"] = self.functionality
        if self.application_name is not None:
            result["application_name"] = self.application_name
        if self.role is not None:
            result["role"] = self.role
        if self.timestamp is not None:
            result["timestamp"] = self.timestamp
        if self.run_id is not None:
            result["run_id"] = self.run_id
        if self.run_time is not None:
            result["run_time"] = self.run_time
        if self.packet_count_shifted is not None:
            result["packet_count_shifted"] = self.packet_count_shifted
        if self.byte_count_shifted is not None:
            result["byte_count_shifted"] = self.byte_count_shifted
        if self.packet_count_average is not None:
            result["packet_count_average"] = self.packet_count_average
        if self.byte_count_average is not None:
            result["byte_count_average"] = self.byte_count_average
        if self.byte_count_average_norm is not None:
            result["byte_count_average_norm"] = self.byte_count_average_norm
        if self.packet_count_average_norm is not None:
            result["packet_count_average_norm"] = self.packet_count_average_norm
        if self.byte_scores is not None:
            result["byte_scores"] = self.byte_scores
        if self.packet_scores is not None:
            result["packet_scores"] = self.packet_scores
        if self.byte_anomaly is not None:
            result["byte_anomaly"] = self.byte_anomaly
        if self.packet_anomaly is not None:
            result["packet_anomaly"] = self.packet_anomaly
        return result

class RxomsLimit(int, Enum):
    """
    Time limit to handle incident, if no anomaly is detected in this time, the incident will be closed
    """
    INCIDENT_TIMEOUT = 60


class RxomsDTType(str, Enum):
    """
    Define type of Digital Twin
    """
    SWITCH = "switch"
    ASSET = "asset"
    GATEWAY = "gateway"


class RxomsStorage(str, Enum):
    """
    Define storage to store security report
    """
    PHYSICAL = "/physical"
    LOGICAL = "/logical"


class RxomsIncidentType(str, Enum):
    """
    Define type of incident with specific ID from MITRE ATT&CK
    """
    DDOS = "T1498"
    DDOSNF = "T1498.001"
    DDOSRA = "T1498.002"
    DM = "T1565"
    DMSDM = "T1565.001"
    DMTDM = "T1565.002"
    DMRDM = "T1565.003"


class RxomsAnomalValue(str, Enum):
    """
    Define value of anomaly
    """
    NORMAL = 1
    ABNORMAL = -1


class RxomsFlowStatus(str, Enum):
    """
    Define status of flow
    """
    OVER = "overflow"
    UNDER = "underflow"


class RxomsDTStatus(str, Enum):
    """
    Define status of DT
    """
    ATTACK = "attack"
    NORMAL = "normal"
    AFFECTED = "affected"


class RxomsResponseStatus(str, Enum):
    """
    Define status of response
    """
    SUCCESS = "success"
    FAILED = "failed"
    ID_NOT_FOUND = "id not found"
    MAC_NOT_FOUND = "mac not found"
    SWITCH_NOT_FOUND = "switch not found"
    FLOW_NOT_FOUND = "flow not found"
    CTI_NOT_FOUND = "cti not found"
    ASSET_NOT_FOUND = "asset not found"
    DT_NOT_FOUND = "digital twin not found"
    ROOT_CAUSE_NOT_FOUND = "root cause not found"
    CONSEQUENCE_NOT_FOUND = "consequence not found"
    SERVER_ERROR = "server error"
    NO_UPDATE = "no update"


class RxomsKnowledgeGraphResource(str, Enum):
    """
    Define resource of knowledge graph service
    """
    GRAPH = "/graph"
    GET_CTI_BY_ID = "/get_cti_by_id"
    GET_DT_BY_MAC = "/get_dt_by_mac"
    GET_FLOW = "/get_flow"
    GET_INCIDENT_METADATA = "/get_incident_metadata"
    UPDATE_CTI_BY_ID = "/update_cti_by_id"
    UPDATE_ASSET_BY_MAC = "/update_asset_by_mac"
    UPDATE_SWITCH = "/update_switch"
    RESET_GRAPH = "/reset_graph"
    UPDATE_FLOW = "/update_flow"
    TRACE_ROOT_CAUSE_BY_FLOW = "/trace_root_cause_by_flow"
    TRACE_ROOT_CAUSE_BY_SWITCH = "/trace_root_cause_by_switch"
    TRACE_CONSEQUENCE_BY_SWITCH = "/trace_consequence_by_switch"
    GET_DETECTOR = "/get_detector"
    GET_INCIDENT = "/get_incident"
    UPDATE_INCIDENT = "/update_incident"
    GET_SWITCH_BY_ID = "/get_switch_by_id"


class RxomsDataEnrichmentResource(str, Enum):
    """
    Define resource of data enrichment service
    """
    ANOMALY_REPORT = "/anomaly_report"


class RxomsIncidentAnalysisResource(str, Enum):
    """
    Define resource of incident analysis service
    """
    INCIDENT_REPORT = "/incident_report"


class RxomsIncidentValidationResource(str, Enum):
    """
    Define resource of incident validation service
    """
    VALIDATE_LOGICAL_REPORT = "/validate_logical_report"


class RxomsPlanEnforcementResource(str, Enum):
    """
    Define resource of plan enforcement service
    """
    PLAN_ENFORCEMENT = "/plan_enforcement"