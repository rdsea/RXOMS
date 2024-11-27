import traceback
import argparse
import logging
from rxoms.utils import rxoms_utils as rutils
from qoa4ml.qoa_client import QoaClient
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import uvicorn
import requests
from rxoms.incident_validation.function import (
    validate_logical_report,
    generate_security_plan,
)
from rxoms.base_model import (
    RxomsLogicalReport,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsIncidentValidationResource,
    RxomsPlanEnforcementResource,
)

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
DEFAULT_CONFIG_FOLDER = "/configuration/service/"
DEFAULT_PATH_LEVEL = 2
DEFAULT_KG_URL = "http://localhost:5000"
DEFAULT_PE_URL = "http://localhost:5004"
DEFAULT_PORT = 5003
DEFAULT_HOST = "0.0.0.0"

# User must export RXOMS_PATH before using
RXOMS_PATH = rutils.get_parent_directory(__file__, DEFAULT_PATH_LEVEL)

parser = argparse.ArgumentParser(description="Incident Validation Service")
parser.add_argument(
    "--config",
    type=str,
    required=False,
    help="Path to the config file",
    default="incident_validation.yaml",
)
args = parser.parse_args()
try:
    config_data = rutils.load_config(
        str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.config
    )
    kg_url = config_data["kg_url"]
    port = config_data["port"]
    host = config_data["host"]
    pe_url = config_data["pe_url"]
    logging.info(f"Loaded config file successfully")
except Exception as e:
    logging.warning("Unable to load config file.")
    logging.warning(traceback.format_exc())
    kg_url = DEFAULT_KG_URL
    port = DEFAULT_PORT
    host = DEFAULT_HOST
    pe_url = DEFAULT_PE_URL
app = FastAPI()

qoa_client = QoaClient(config_dict=config_data["qoa_config"])

@app.post(RxomsIncidentValidationResource.VALIDATE_LOGICAL_REPORT)
def post_validate_logical_report(request: RxomsLogicalReport):
    try:
        # Validate incident
        report_validation = validate_logical_report(kg_url, request)
        security_plan = generate_security_plan(kg_url, request)
        if report_validation:
            logging.info("Incident is valid")
            enforce_response = requests.post(
                str(pe_url) + RxomsPlanEnforcementResource.PLAN_ENFORCEMENT,
                json=security_plan.__to_dict__(),
            )
            logging.info(f"Enforce security plan response: {enforce_response.json()}")
            qoa_client.report(report=request.__to_dict__(), submit=True)
        else:
            logging.info("Incident is invalid")
        result = RxomsResponse(
            status=RxomsResponseStatus.SUCCESS,
            data={"report_validation": report_validation},
        )
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


if __name__ == "__main__":
    uvicorn.run("incident_validation:app", host=host, port=port, reload=True)
