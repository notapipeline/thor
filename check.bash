#!/bin/bash
# Helper script for building the binaries and trusting them in thor server

# curl -kvvvL -X POST -H 'Content-Type: application/json' -d '{"devices":["127.0.0.1"]}' https://localhost:9100/api/v1/adddevices
# curl -kvvvL -X POST -H 'Content-Type: application/json' -d '{"registration_request":1}' https://localhost:9100/api/v1/register

user=$1
server=$2

make build

scp thor ${user}@${server}:
ssh ${user}@${server} -- 'sudo mv thor /usr/local/bin/thor'
ssh ${user}@${server} -- 'sudo systemctl restart thor'

linux=$(sha256sum thor | awk '{print $1}')
windows=$(sha256sum thor.exe | awk '{print $1}')

comm="curl -kvvvL -H 'Content-Type: application/json' -d '{\"shas\":[{\"sha\":\"$linux\",\"name\":\"thor\"},{\"sha\":\"$windows\",\"name\":\"thor.exe\"}]}' https://localhost:9100/api/v1/shasum"
ssh ${user}@${server} -- ${comm}

