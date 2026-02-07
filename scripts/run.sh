#!/bin/bash

set -e
set -u

if [ -e ./firmweld.config ]; then
    source ./firmweld.config
elif [ -e ../firmweld.config ]; then
    source ../firmweld.config
else
    echo "Error: Could not find 'firmweld.config'!"
    exit 1
fi

if check_number $1; then
    echo "Usage: run.sh <image ID> [<architecture>]"
    exit 1
fi

IID=${1}
ARCH=${2}

${SCRIPT_DIR}/run.${ARCH}.sh ${IID}
