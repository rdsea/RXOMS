# RXOMS Configuration

## ML Tool Configuration
- Each ML tool detect anomaly on separate network flow, the list of network flows is provided in [configuration/mltool/flow.yaml](mltool/flow.yaml)
- The tool ID, ML algorithm and incident type of the ML-based detection tool is defined in [configuration/mltool/train.yaml](mltool/train.yaml)
- The network flows can be modified following the network topology.

## SINDIT Network Configuration
- The configuration specifies IP address, ID of switches, port connections between components in SINDIT network. The configuration is provided in [configuration/network](network) folder.
- Users can change the port connection to modify the network topology.

## Monitoring Configuration
- The monitoring configuration is provided in [configuration/qoa](qoa) folder.
- Since the monitoring probes are implemented using [QoA4ML](https://github.com/rdsea/QoA4ML) library, the configuration provide the endpoint of a message broker and some information about the monitored instances.
- Users can change the configuration to use other message brokers or message queues.

## Service Configuration
- The service configuration is provided in [configuration/service](service) folder.
- The folder contains the configuration of the services in RXOMS.
- Services:
    - Knowledge graph service: The configuration is provided in [configuration/service/simulated_kg.yaml](service/simulated_kg.yaml).
    - Data enrichment service: The configuration is provided in [configuration/service/data_enrichment.yaml](service/data_enrichment.yaml).
    - Incident analysis service: The configuration is provided in [configuration/service/incident_analysis.yaml](service/incident_analysis.yaml).
    - Incident validation service: The configuration is provided in [configuration/service/incident_validation.yaml](service/incident_validation.yaml).
    - Plan enforement service: The configuration is provided in [configuration/service/plan_enforcement.yaml](service/plan_enforcement.yaml).
- Users can change the configuration to modify the host and port to start the service, and the endpoint to connect to other services.
- The folder also provide some configuration for testing the services.

## Simulation Configuration
- The simulation configuration is provided in [configuration/simulation](simulation) folder.
- Users can change the configuration to modify the simulation scenario, such as the number of incidents, the time interval between incidents, network flow, etc.
    