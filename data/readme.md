# Data used in RXOMS experiments

## Anomaly detection data
- The data is stored in the [data/anomaly_data](anomaly_data) folder.
- The data collect all anomalies detected from all network flows in SINDIT simulated network, using 2 ML-based security tools. One tool uses Local Outlier Factor, the other uses Isolation Forest. The model is saved at [sdn_simulation/ml_detection/artifact](../sdn_simulation/ml_detection/artifact) folder.

## Graph data
- The data is used to initiate the knowledge graph for experiments with SINDIT network.
- The data is stored in the [data/graph](graph) folder with 2 formats JSON and YAML.

## Metadata
- The data is stored in the [data/metadata](metadata) folder.
- The data includes the metadata of components in SINDIT simulation ([componentData](metadata/componentData.json)), incident metadata ([incidentMetadata](metadata/incidentMetadata.json)), and the migigation metadata ([mitigationMetadata](metadata/mitigationMetadata.json)).

## Digital twin data
- The data is stored in the [data/normalizedDT](normalizedDT) folder.
- The data is normalized from the raw data of the digital twins in the SINDIT network, representing the network traffic from different components to specific gateways.
- Components: Delivery and Pickup (DPS), Highbay Warehouse (HBW), Sorting Line (SLD), Sensor Unit (SSC), Robot (VGR), and Multi-Processing Station (MPO).
- Gateways: MQTT and OPC-UA.

## RXOMS Reports
- The data is stored in the [data/rxoms_reports](rxoms_reports) folder.
- The data includes physical and logical reports, stored in separate folders.
- The report is generated when running RXOMS services with the SINDIT network data.

## SINDIT network data
- The data is stored in the [data/sdn_simulation](sdn_simulation) folder.
- The data is generate by running the simulation in [sdn_simulation](../sdn_simulation) folder.
- The data includes the network traffic data, collected from all network flows in the SINDIT network.
- The data is used to detect anomalies and generate the anomaly detection data.

## Template data
- The data provides template of different data desigened for the RXOMS experiments.
- The data includes:
    - `api.json` for API calls and parameters for different protection services.
    - `cti.json` for Cyber Threat Intelligence data.
    - `detectorData.json` for detector information.
    - `plan.json` for the security plan for RXOMS plan enforcement.
    - `protectorData.json` for protector information.

## More detail information of incident and mitigation
- The data is stored in the [data/textData](textData) folder.
- The data provide link to online source of the incident and mitigation information.