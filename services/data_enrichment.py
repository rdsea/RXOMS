import traceback
import argparse
import logging
from rxoms.utils import rxoms_utils as rutils
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import uvicorn
from rxoms.data_enrichment.function import enrich_anomaly_report, send_physical_report
from rxoms.base_model import (
    RxomsSinditReport,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsDataEnrichmentResource,
)

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
DEFAULT_CONFIG_FOLDER = "/configuration/service/"
DEFAULT_PATH_LEVEL = 2
DEFAULT_KG_URL = "http://localhost:5000"
DEFAULT_PORT = 5001
DEFAULT_HOST = "0.0.0.0"

# User must export RXOMS_PATH before using
RXOMS_PATH = rutils.get_parent_directory(__file__, DEFAULT_PATH_LEVEL)

parser = argparse.ArgumentParser(description="Data Enrichment Service")
parser.add_argument(
    "--config",
    type=str,
    required=False,
    help="Path to the config file",
    default="data_enrichment.yaml",
)
args = parser.parse_args()
try:
    config_data = rutils.load_config(
        str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.config
    )
    kg_url = config_data["kg_url"]
    ia_url = config_data["ia_url"]
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


@app.post(RxomsDataEnrichmentResource.ANOMALY_REPORT)
def post_anomaly_report(request: RxomsSinditReport):
    try:
        logging.debug(f"Received request: {request}")
        # Create physical report
        physical_report = enrich_anomaly_report(kg_url, request)
        # Forward physical report to the incident analysis service
        response_dict = send_physical_report(ia_url, physical_report)
        if response_dict is not None:
            result = RxomsResponse(status=RxomsResponseStatus.SUCCESS)
        else:
            result = RxomsResponse(
                status=RxomsResponseStatus.FAILED,
                error="Failed to send physical report",
            )
        logging.info("Physical report sent")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


if __name__ == "__main__":
    uvicorn.run("data_enrichment:app", host=host, port=port, reload=True)
