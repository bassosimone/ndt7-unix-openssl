#!/bin/bash
set -ex
mlabnsdata=$(curl -vs https://locate-dot-mlab-staging.appspot.com/ndt_ssl)
echo "mlabnsdata: $mlabnsdata" 1>&2
hostname=$(echo $mlabnsdata | jq .fqdn | tr -d \")
echo "hostname: $hostname" 1>&2
$(cd $(dirname $0) && pwd -P)/ndt7-unix-openssl -hostname $hostname "$@"
