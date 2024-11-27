import logging
import traceback

from rxoms.base_model import (
    RxomsLogicalReport,
    RxomsSecurityPlan,
)

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.INFO
)

# TODO: Implement the function validate the logical report


def validate_logical_report(ulr: str, request: RxomsLogicalReport):
    try:
        # Todo implement function to interact with security expert
        return True
    except Exception as e:
        logging.error(f"Error when validate_logical_report: {e}")
        logging.error(traceback.format_exc())
        return False


def generate_security_plan(ulr: str, request: RxomsLogicalReport):
    try:
        # Todo implement function to generate security plan
        return RxomsSecurityPlan.model_validate({"T1498": "M1037"})
    except Exception as e:
        logging.error(f"Error when create_security_plan: {e}")
        logging.error(traceback.format_exc())
        return None
