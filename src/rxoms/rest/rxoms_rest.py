import logging

from flask import Flask, jsonify, request
from flask_restful import Api, Resource

logging.basicConfig(
    format="%(asctime)s:%(levelname)s -- %(message)s", level=logging.NOTSET
)


class RxomsRestResource(Resource):
    def __init__(self, **kwargs) -> None:
        super().__init__()
        self.config = kwargs

    def get(self):
        # Processing GET request
        args = request.query_string.decode("utf-8").split("&")
        # get param from args here
        return jsonify({"status": args})

    def post(self):
        # Processing GET request
        args = request.query_string.decode("utf-8").split("&")
        # get param from args here
        return jsonify({"status": args})

    def put(self):
        if request.is_json:
            request.get_json(force=True)
        # get param from args here
        return jsonify({"status": True})

    def delete(self):
        if request.is_json:
            args = request.get_json(force=True)
        # get param from args here
        return jsonify({"status": args})


class RxomsService:
    def __init__(self, config=None) -> None:
        if config is None:
            config = {}
        super().__init__()
        self.app = Flask(__name__)
        self.api = Api(self.app)
        self.config = config

    def add_resource(self, object_class, url):
        # Run Service
        self.api.add_resource(object_class, url, resource_class_kwargs=self.config)

    def run(self, debug=True, port=5010, host="0.0.0.0"):
        self.app.run(debug=debug, port=port, host=host, use_reloader=False)
