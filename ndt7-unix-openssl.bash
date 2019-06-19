#!/bin/bash
set -ex
mlabnsdata=$(curl -vs https://locate.measurementlab.net/ndt7)
echo "mlabnsdata: $mlabnsdata" 1>&2
hostname=$(echo $mlabnsdata | jq -r .fqdn)
echo "hostname: $hostname" 1>&2
$(cd $(dirname $0) && pwd -P)/ndt7-unix-openssl -hostname $hostname "$@"
