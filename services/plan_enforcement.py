import traceback
import argparse
import logging
import requests
from rxoms.utils import rxoms_utils as rutils
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import uvicorn
from rxoms.plan_enforcement.function import enforce_security_plan
from rxoms.base_model import (
    RxomsSecurityPlan,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsPlanEnforcementResource,
)

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
DEFAULT_CONFIG_FOLDER = "/configuration/service/"
DEFAULT_PATH_LEVEL = 2
DEFAULT_KG_URL = "http://localhost:5000"
DEFAULT_PORT = 5004
DEFAULT_HOST = "0.0.0.0"

# User must export RXOMS_PATH before using
RXOMS_PATH = rutils.get_parent_directory(__file__, DEFAULT_PATH_LEVEL)

parser = argparse.ArgumentParser(description="Incident Analysis Service")
parser.add_argument(
    "--config",
    type=str,
    required=False,
    help="Path to the config file",
    default="plan_enforcement.yaml",
)
args = parser.parse_args()
try:
    config_data = rutils.load_config(
        str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.config
    )
    kg_url = config_data["kg_url"]
    port = config_data["port"]
    host = config_data["host"]
    logging.info(f"Loaded config file successfully")
except Exception as e:
    logging.warning("Unable to load config file.")
    logging.warning(traceback.format_exc())
    kg_url = DEFAULT_KG_URL
    port = DEFAULT_PORT
    host = DEFAULT_HOST
app = FastAPI()


@app.post(RxomsPlanEnforcementResource.PLAN_ENFORCEMENT)
def post_enforce_security_plan(request: RxomsSecurityPlan):
    try:
        logging.debug(f"Received request: {request}")
        # Analyse incident
        enforcement_result = enforce_security_plan(kg_url, request)
        if enforcement_result is None:
            logging.info("No plan is applied")
        else:
            logging.info(f"Planenforced: {enforcement_result}")
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
    uvicorn.run("plan_enforcement:app", host=host, port=port, reload=True)
