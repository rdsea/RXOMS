import traceback
import argparse
from rxoms.base_model import (
    RxomsCTI,
    RxomsDT,
    RxomsFlow,
    RxomsSwitch,
    RxomsResponse,
    RxomsResponseStatus,
    RxomsKnowledgeGraphResource,
    RxomsDetector,
    RxomsLogicalReport,
)
from rxoms.knowledge_graph.function import (
    get_cti_by_id,
    get_dt_by_mac,
    get_flow,
    get_incident_metadata,
    update_cti_by_id,
    update_asset_by_mac,
    update_switch,
    update_flow,
    trace_root_cause_by_flow,
    trace_root_cause_by_switch,
    trace_consequence_by_switch,
    get_detector,
    get_incident,
    update_incident,
    get_switch_by_id,
    init_graph_in_db,
    get_graph_from_db,
)
import logging
from rxoms.utils import rxoms_utils as rutils
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import uvicorn



logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)
DEFAULT_GRAPH_FOLDER = "/data/graph/"
DEFAULT_CONFIG_FOLDER = "/configuration/service/"
DEFAULT_PATH_LEVEL = 2
DEFAULT_PORT = 5000
DEFAULT_HOST = "0.0.0.0"

# User must export RXOMS_PATH before using
RXOMS_PATH = rutils.get_parent_directory(__file__, DEFAULT_PATH_LEVEL)
parser = argparse.ArgumentParser(description="Simulated Knowledge Graph")
parser.add_argument(
    "--graph",
    type=str,
    required=False,
    help="Path to the graph file",
    default="graph.yml",
)
parser.add_argument(
    "--config",
    type=str,
    required=False,
    help="Path to the config file",
    default="simulated_kg.yaml",
)
parser.add_argument(
    "--db",
    type=str,
    required=False,
    help="Path to the config file",
    default="db_credential.yaml",
)
args = parser.parse_args()
try:
    graph_data = rutils.load_config(str(RXOMS_PATH) + DEFAULT_GRAPH_FOLDER + args.graph)
except Exception as e:
    logging.error("Unable to load graph file.")
    logging.error(traceback.format_exc())
    graph_data = None

try:
    credential_data = rutils.load_config(str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.db)
    logging.info(f"Loaded db credential file successfully")
except Exception as e:
    logging.error("Unable to load db credential file.")
    logging.error(traceback.format_exc())
    credential_data = None
try:
    config_data = rutils.load_config(
        str(RXOMS_PATH) + DEFAULT_CONFIG_FOLDER + args.config
    )
    port = config_data["port"]
    host = config_data["host"]
    mongo_config = config_data["mongo_config"]
    logging.info(f"Loaded config file successfully")
except Exception as e:
    logging.warning("Unable to load config file.")
    logging.warning(traceback.format_exc())
    port = DEFAULT_PORT
    host = DEFAULT_HOST

mongo_client = None
app = FastAPI()    



@app.get(RxomsKnowledgeGraphResource.GRAPH)
def get_graph():
    try:
        logging.debug("GET /graph Request received")

        rxoms_response = get_graph_from_db(mongo_config, credential_data)
        logging.info(f"get graph success")
        return JSONResponse(content=rxoms_response.__to_dict__())
    except Exception as e:
        logging.error(f"Error in GET /graph: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_CTI_BY_ID)
def post_get_cti_by_id(request: RxomsCTI):
    try:
        logging.debug(
            f"POST /post_get_cti_by_id Request received with id: {request.id}"
        )
        result = get_cti_by_id(mongo_config, credential_data, request)
        logging.info(f"get cti by id success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /post_get_cti_by_id: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_DT_BY_MAC)
def post_get_dt_by_mac(request: RxomsDT):
    try:
        logging.debug(f"POST /post_get_dt_by_mac Request received with MAC: {request}")
        result = get_dt_by_mac(mongo_config, credential_data, request)
        logging.info(f"get dt by mac success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /post_get_dt_by_mac: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_FLOW)
def post_get_flow(request: RxomsFlow):
    try:
        logging.debug(f"POST /post_get_flow Request received with flow: {request}")
        result = get_flow(mongo_config, credential_data, request)
        logging.info(f"get flow success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /post_get_flow: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_INCIDENT_METADATA)
def post_get_incident_metadata(request: RxomsCTI):
    try:
        logging.debug(
            f"POST /get_incident_metadata Request received with id: {request}"
        )
        result = get_incident_metadata(mongo_config, credential_data, request)
        logging.info(f"get incident metadata success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /get_incident_metadata: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.UPDATE_CTI_BY_ID)
def post_update_cti_by_id(request: RxomsCTI):
    try:
        logging.debug(f"POST /update_cti_by_id Request received with id: {request.id}")
        result = update_cti_by_id(mongo_config, credential_data, request)
        logging.info(f"update cti by id success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /update_cti_by_id: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.UPDATE_ASSET_BY_MAC)
def post_update_asset_by_mac(request: RxomsDT):
    try:
        logging.debug(
            f"POST /update_asset_by_mac Request received with MAC: {request.mac}"
        )
        result = update_asset_by_mac(mongo_config, credential_data, request)
        logging.info(f"update asset by mac success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /update_asset_by_mac: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_SWITCH_BY_ID)
def post_get_switch_by_id(request: RxomsSwitch):
    try:
        logging.debug(f"POST /get_switch_by_id Request received with id: {request.id}")
        result = get_switch_by_id(mongo_config, credential_data, request)
        logging.info(f"get switch by id success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /get_switch_by_id: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.UPDATE_SWITCH)
def post_update_switch(request: RxomsSwitch):
    try:
        logging.debug(f"POST /update_switch Request received with data: {request}")
        result = update_switch(mongo_config, credential_data, request)
        logging.info(f"update switch success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /update_switch: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.get(RxomsKnowledgeGraphResource.RESET_GRAPH)
def get_reset_graph():
    try:
        logging.debug("GET /reset_graph Request received")
        graph_data = rutils.load_config(
            str(RXOMS_PATH) + DEFAULT_GRAPH_FOLDER + args.graph
        )
        init_graph_in_db(graph_data, mongo_config, credential_data)
        result = RxomsResponse(status="success")
        logging.info(f"reset graph success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in GET /reset_graph: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.UPDATE_FLOW)
def post_update_flow(request: RxomsFlow):
    try:
        logging.debug(f"POST /update_flow Request received with data: {request}")
        result = update_flow(mongo_config, credential_data, request)
        logging.info(f"update flow success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /update_flow: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.TRACE_ROOT_CAUSE_BY_FLOW)
def post_trace_root_cause_by_flow(request: RxomsFlow):
    try:
        logging.debug(
            f"POST /trace_root_cause_by_flow Request received with data: {request}"
        )
        result = trace_root_cause_by_flow(mongo_config, credential_data, request)
        logging.info(f"trace root cause by flow success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /trace_root_cause_by_flow: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.TRACE_ROOT_CAUSE_BY_SWITCH)
def post_trace_root_cause_by_switch(request: RxomsSwitch):
    try:
        logging.debug(
            f"POST /trace_root_cause_by_switch Request received with data: {request}"
        )
        result = trace_root_cause_by_switch(mongo_config, credential_data, request)
        logging.info(f"trace root cause by switch success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /trace_root_cause_by_switch: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.TRACE_CONSEQUENCE_BY_SWITCH)
def post_trace_consequence_by_switch(request: RxomsSwitch):
    try:
        logging.debug(
            f"POST /trace_consequence_by_switch Request received with data: {request}"
        )
        result = trace_consequence_by_switch(mongo_config, credential_data, request)
        logging.info(f"trace consequence by switch success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /trace_consequence_by_switch: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_DETECTOR)
def post_get_detector(request: RxomsDetector):
    try:
        logging.debug(f"POST /get_detector Request received with data: {request}")
        result = get_detector(mongo_config, credential_data, request)
        logging.info(f"get detector success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /get_detector: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.GET_INCIDENT)
def post_get_incident(request: RxomsDT):
    try:
        logging.debug(f"POST /get_incident Request received with data: {request}")
        result = get_incident(mongo_config, credential_data, request)
        logging.info(f"get incident success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /get_incident: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


@app.post(RxomsKnowledgeGraphResource.UPDATE_INCIDENT)
def post_update_incident(request: RxomsLogicalReport):
    try:
        logging.debug(f"POST /update_incident Request received with data: {request}")
        result = update_incident(mongo_config, credential_data, request)
        logging.info(f"update incident success")
        return JSONResponse(content=result.__to_dict__())
    except Exception as e:
        logging.error(f"Error in POST /update_incident: {e}")
        logging.error(traceback.format_exc())
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=RxomsResponseStatus.SERVER_ERROR,
        )


if __name__ == "__main__":
    if mongo_config and credential_data:
        init_graph_in_db(graph_data, mongo_config, credential_data)
    uvicorn.run("simulated_KG:app", host=host, port=port, reload=True)
