import pandas as pd
import argparse
import sys, pathlib

current_path = str(pathlib.Path(__file__).parent.absolute())

if __name__ == "__main__":
    # Set parameter
    parser = argparse.ArgumentParser(description="Processing SINDIT Data")
    parser.add_argument("--category", help="category file", default="/factory.csv")
    parser.add_argument("--path", help="default data path", default="/sensor_data/")
    parser.add_argument("--out", help="default output path", default="/processed_data/")

    # Parse the parameters
    args = parser.parse_args()
    category_file = current_path + args.category
    data_path = current_path + args.path
    out_path = current_path + args.out

    category_df = pd.read_csv(category_file)
    dict_df = {}
    # Group and convert sensor data
    for _, row in category_df.iterrows():
        if row["Asset"] not in dict_df:
            dict_df[row["Asset"]] = {}
        if row["Gateway"] not in dict_df[row["Asset"]]:
            dict_df[row["Asset"]][row["Gateway"]] = pd.DataFrame(
                [], columns=["unixtime"]
            )
        file_name = data_path + str(row["File"]) + ".csv"
        idf = pd.read_csv(file_name)
        idf["unixtime"] = pd.to_datetime(idf["time"], format="mixed")
        dict_df[row["Asset"]][row["Gateway"]] = pd.concat(
            [
                dict_df[row["Asset"]][row["Gateway"]],
                pd.DataFrame(idf["unixtime"].astype(int)),
            ],
            ignore_index=True,
            sort=True,
        )

    # Normalize timestamp
    count_dict = {}
    for asset_key in dict_df:
        asset = dict_df[asset_key]
        count_dict[asset_key] = {}
        for gateway_key in asset:
            gateway = asset[gateway_key]
            gateway = gateway.sort_values(by=["unixtime"])
            gateway["nor_unixtime"] = (
                (gateway["unixtime"] - gateway["unixtime"].min()) / 10**9 / 1440
            )  # 10**9: nano second -> second; 1440: 10 days -> 10 minutes
            gateway["nor_unixtime"] = gateway["nor_unixtime"].astype(int)
            asset[gateway_key] = gateway
            count_dict[asset_key][gateway_key] = gateway.groupby(
                ["nor_unixtime"]
            ).count()

            count_dict[asset_key][gateway_key].to_csv(
                out_path + asset_key + "_" + gateway_key + ".csv"
            )
            print(count_dict[asset_key][gateway_key].shape)
        # print(gateway.shape)
    print(count_dict)
