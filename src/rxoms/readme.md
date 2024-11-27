# Security Report Prototype
- The security report prototypes are defined in `base_model.py`.
## Physical Prototype

- Class `RxomsPhysicalReport` is the prototype for the security report at physical layer. It can be used to report anomalies in the physical layer. The report includes the following attributes:
    - `id`: The unique identifier of the report.
    - `detector`: The tool that detected the anomaly.
    - `anomaly`: The anomaly detected.
    - `monitor`: The monitor provide data supporting the detection.
    - `physical_entity` : The physical entity where the anomaly was detected.
    - `report_time`: The time when the report was generated.
- Class `RxomsDetector` is the prototype for the detector. It includes the following attributes:
    - `id`: The unique identifier of the detector.
    - `detector_name`: The name of the detector.
    - `ml_algorithm`: The machine learning algorithm used by the detector.
    - `last_update`: The time when the detector was last updated (e.g., retrain the ML model).
    - `detection_time`: The time when the detector detected the anomaly.
    - `configuration`: The current configuration of the detector.
    - `detecting`: The list of entities that the detector is managing.
    - `metadata`: The metadata of the detector.
    - `performance`: The current performance of the detector.
-Class `RxomsAnomaly`: The prototype for reporting anomaly. It includes the following attributes:
    - `id`: The unique identifier of the anomaly.
    - `common_metric`: The common metric used to detect the anomaly.
    - `ml_metric`: The machine learning metric used to detect the anomaly.
    - `anomaly_result`: The result of the anomaly detection.
    - `anomaly_flow`: The flow of the anomaly detected (only apply for detecting flow anomaly).
- Class `RxomsMonitor` is the prototype for the monitor. It includes the following attributes:
    - `user_id`: The unique identifier of the monitoring probe.
    - `instance_id`: The unique identifier of the monitored instance.
    - `stage_id`: The unique identifier of the monitored stage.
    - `functionality`: The functionality of the monitored instance.
    - `application_name`: The name of the monitored application.
    - `role`: The role of the monitored instance.
    - `monitoring_time`: The time when the monitoring data was collected.
- Class `RxomsDT` is the prototype for the digital twin instance. It includes the following attributes:
    - `id`: The unique identifier of the digital twin.
    - `mac`: The MAC address of the digital twin.
    - `ip`: The IP address of the digital twin.
    - `status`: The status of the digital twin.
    - `type`: The type of the digital twin.
    - `last_update`: The time when the digital twin was last updated.
    - `name`: The name of the digital twin.
    - `norm_value`: The normal values of the digital twin.

## Logical Prototype
- Class `RxomsLogicalReport` is the prototype for the security report at logical layer. It can be used to report incident in the logical layer. The report includes the following attributes:
    - `id`: The unique identifier of the report.
    - `incident`: A dictionary that contains the information of the incident (each incident is as type `RxomsIncident`).
    - `incident_cause`: The cause of the incident.
    - `incident_consequence`: The consequence of the incident.
   

- Class `RxomsIncident` is the prototype for the incident. It includes the following attributes:
    - `id`: The unique identifier of the incident.
    - `incident_type`: The type of the incident.
    - `incident_metadata`: Metadata of the incident providing readable information about the incident for security analyst.
    - `metrics`: The metrics related to the incident
    - `runtime_pattern`: The runtime pattern of the incident.
    - `last_update` : The time when the incident was last updated.

- Class `RxomsIncidentCause` is the prototype for the incident cause. It includes the following attributes:
    - `root_cause`: The root cause of the incident - dictionary containing the entities causing the incident.

- Class `RxomsIncidentConsequence` is the prototype for the incident consequence. It includes the following attributes:
    - `target_dt`: The target digital twin of the incident.
    - `affected_dt`: The affected digital twin of the incident.

## Other Prototypes
- Class `RxomsCTI` is the prototype for the Cyber Threat Intelligence. It includes the following attributes:
    - `id`: The unique identifier of the CTI.
    -  `mitigation`: The mitigation of the CTI.

- Class `RxomsFlow` is the prototype for network flow. It includes the following attributes:
    - `id`: The unique identifier of the flow.
    - `eth_dst`: The destination MAC address of the flow.
    - `switch`: The switch that the flow is passing through.
    - `in_port`: The input port of the flow.
    - `last_update`: The time when the flow was last updated.
    - `mean_byte_count`: The normal byte count of the flow.
    - `mean_packet_count`: The normal packet count of the flow.
    - `recent_byte_value`: The recent byte count of the flow.
    - `recent_packet_value`: The recent packet count of the flow.
    - `status`: The status of the flow.

- Class `RxomsSwitch` is the prototype for the switch, inherited from `RxomsDT`. In addition to the attributes of the `RxomsDT`, it includes the following attributes:
    - `max_byte`: The maximum byte capacity of the switch.
    - `max_packet`: The maximum packet capacity of the switch.
    - `port`: The dictionary includes DTs connected to ports of the switch.
    - `sum_byte`: The sum of byte count of the flows passing through the switch.
    - `sum_packet`: The sum of packet count of the flows passing through the switch.

- Class `RxomsResponse` is the prototype for the response from RXOMS's services. It includes the following attributes:
    - `status`: The status of the response.
    - `data`: The data of the response.
    - `error`: The error message if the request is processed with error.

- Class `RxomsProtector` is the prototype for the protector. It includes the following attributes:
    - `tool_id`: The unique identifier of the protector.
    - `functionality`: The functionality of the protector.
    - `last_update`: The time when the protector was last updated.

- Class `RxomsIncidentTime` is the prototype for the incident time. It includes the following attributes:
    - `start_time`: The start time of the incident.
    - `duration`: The duration of the incident.

- Class `RxomsIncidentPattern` is the prototype for the incident pattern. It includes the following attributes:
    - `incident_time`: The time when the incident was detected.
    - `pattern`: The pattern of the incident.

- Class `RxomsSecurityPlan` is the prototype for the security plan. It includes the following attributes:
    - `plan`: The plan of the security.

- Class `RxomsSinditReport` is the prototype for the monitoring report from the SINDIT network.