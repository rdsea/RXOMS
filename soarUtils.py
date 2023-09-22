import yaml, json


def to_json(file_path:str, conf:dict):
    """
    file_path: file path to save config
    """
    with open(file_path, "w") as f:
        json.dump(conf, f)

def to_yaml(file_path:str, conf:dict):
    """
    file_path: file path to save config
    """
    with open(file_path, "w") as f:
        yaml.dump(conf, f, default_flow_style=False)

def load_config(file_path:str)->dict:
    """
    file_path: file path to load config
    """
    try:
        if 'json' in file_path:
            with open(file_path, "r") as f:
                return json.load(f)
        if ('yaml' in file_path) or ('yml' in file_path):
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return None
    except yaml.YAMLError as exc:
        print(exc)