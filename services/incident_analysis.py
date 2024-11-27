import traceback
import argparse
import logging
import requests
from rxoms.utils import rxoms_utils as rutils
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import uvicorn
from rxoms.incident_analysis.function import analyse_incident
from rxoms.base_model import (
    RxomsPhysicalReport,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsIncidentAnalysisResource,
    RxomsIncidentValidationResource,
)

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
DEFAULT_CONFIG_FOLDER = "/configuration/service/"
DEFAULT_DATA_FOLDER = "/data/rxoms_reports/"
DEFAULT_PATH_LEVEL = 2
DEFAULT_KG_URL = "http://localhost:5000"
DEFAULT_IV_URL = "http://localhost:5003"
DEFAULT_PORT = 5001
DEFAULT_HOST = "0.0.0.0"

# User must export RXOMS_PATH before using
RXOMS_PATH = rutils.get_parent_directory(__file__, DEFAULT_PATH_LEVEL)

parser = argparse.ArgumentParser(description="Incident Analysis Service")
parser.add_argument(
    "--config",
    type=str,
    required=False,
    help="Path to the config file",
    default="incident_analysis.yaml",
)
args = parser.parse_args()
try:
    config_data = rutils.load_config(
        str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.config
    )
    kg_url = config_data["kg_url"]
    iv_url = config_data["iv_url"]
    port = config_data["port"]
    host = config_data["host"]
    log_physical_report = bool(config_data["log_physical_report"])
    logging.info(f"Loaded config file successfully")
except Exception as e:
    logging.warning("Unable to load config file.")
    logging.warning(traceback.format_exc())
    kg_url = DEFAULT_KG_URL
    port = DEFAULT_PORT
    host = DEFAULT_HOST
    iv_url = DEFAULT_IV_URL
    log_physical_report = False
app = FastAPI()


@app.post(RxomsIncidentAnalysisResource.INCIDENT_REPORT)
def post_anomaly_report(request: RxomsPhysicalReport):
    try:
        logging.debug(f"Received request: {request}")
        data_path = str(RXOMS_PATH) + DEFAULT_DATA_FOLDER
        # Analyse incident
        logical_report = analyse_incident(
            kg_url, request, data_path, log_physical_report
        )
        if logical_report is None:
            logging.info("No incident detected")
        else:
            logging.info(f"Incident detected - Logical report: {logical_report}")
            validation_response = requests.post(
                str(iv_url) + RxomsIncidentValidationResource.VALIDATE_LOGICAL_REPORT,
                json=logical_report.__to_dict__(),
            )
            logging.info(f"Validation response: {validation_response.json()}")
        result = RxomsResponse(status=RxomsResponseStatus.SUCCESS)
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


if __name__ == "__main__":
    uvicorn.run("incident_analysis:app", host=host, port=port, reload=True)
