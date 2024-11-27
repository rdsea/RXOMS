import logging
import traceback

from rxoms.base_model import RxomsSecurityPlan

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)

# TODO: Implement the function to enforce security plan


def enforce_security_plan(ulr: str, request: RxomsSecurityPlan):
    try:
        # Todo implement function to interact with knowledge graph to enforce security plan
        return True
    except Exception as e:
        logging.error(f"Error when enforce_security_plan: {e}")
        logging.error(traceback.format_exc())
        return False
