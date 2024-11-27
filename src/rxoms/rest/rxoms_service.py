import argparse
import traceback

from ..utils import rxoms_utils
from ..utils.common import RXOMS_PATH
from .rxoms_rest import RxomsRestResource, RxomsService

DEFAULT_CONFIG_PATH = "/config/observationConfigLocal.yaml"

if __name__ == "__main__":
    # init_env_variables()
    parser = argparse.ArgumentParser(
        description="Argument for Rohe Observation Service"
    )
    parser.add_argument("--conf", help="configuration file", default=None)
    parser.add_argument("--port", help="default port", default=5010)

    # Parse the parameters
    args = parser.parse_args()
    config_file = args.conf
    # config_path = args.path
    port = int(args.port)

    # load configuration file
    if not config_file:
        config_file = RXOMS_PATH + DEFAULT_CONFIG_PATH
        print(config_file)

    try:
        configuration = rxoms_utils.load_config(config_file)
        observation_service = RxomsService(configuration)
        observation_service.add_resource(RxomsRestResource, "/agent")
        observation_service.run(port=port)
    except Exception:
        traceback.print_exc()
