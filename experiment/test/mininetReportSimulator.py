import sys, os, argparse, json, time
from qoa4ml.QoaClient import QoaClient
from qoa4ml import qoaUtils

RXOMS_PATH = os.getenv("RXOMS_PATH")
sys.path.append(RXOMS_PATH)

log_path = RXOMS_PATH + "/log/report/"


# Main function
if __name__ == "__main__":
    # Loading default parameter values
    parser = argparse.ArgumentParser(description="Generate Mininet Traffic Report")
    parser.add_argument("--log", help="category file", default="/log/report/")
    parser.add_argument("--run", help="Experiment Run ID", default=1)

    # Parse the parameters
    args = parser.parse_args()
    log_file = RXOMS_PATH + args.log + str(args.run) + "/report.txt"
    config_file = RXOMS_PATH + "/configuration/qoaConfig.yaml"
    qoa_config = qoaUtils.load_config(config_file)
    qoa_client = QoaClient(
        config_dict=qoa_config, registration_url=qoa_config["registration_url"]
    )
    report_data = open(log_file)
    data_lines = report_data.readlines()
    while True:
        line_count = 0
        for line in data_lines:
            jstring = line.replace("'", '"')
            line_dict = json.loads(jstring)
            report = qoa_client.report(report=line_dict, submit=True)
            print("Sending Report {}".format(line_count))
            line_count += 1
            time.sleep(1)
