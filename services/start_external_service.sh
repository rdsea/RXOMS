#!/bin/bash

# docker run -d \
#   --name mongodb \
#   -e MONGO_INITDB_ROOT_USERNAME=admin \
#   -e MONGO_INITDB_ROOT_PASSWORD=admin \
#   -p 27017:27017 \
#   mongo
#
# docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:management

# Check if MongoDB container exists
if [ ! "$(docker ps -q -f name=mongodb)" ]; then
  if [ "$(docker ps -aq -f status=exited -f name=mongodb)" ]; then
    # Cleanup
    docker rm mongodb
  fi
  # Run MongoDB container
  docker run -d \
    --name mongodb \
    -e MONGO_INITDB_ROOT_USERNAME=admin \
    -e MONGO_INITDB_ROOT_PASSWORD=admin \
    -p 27017:27017 \
    mongo
else
  echo "MongoDB container is already running."
fi

# Check if RabbitMQ container exists
if [ ! "$(docker ps -q -f name=rabbitmq)" ]; then
  if [ "$(docker ps -aq -f status=exited -f name=rabbitmq)" ]; then
    # Cleanup
    docker rm rabbitmq
  fi
  # Run RabbitMQ container
  docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:management
else
  echo "RabbitMQ container is already running."
fi
