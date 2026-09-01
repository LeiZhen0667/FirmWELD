#!/bin/bash

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo $0: Usage: ./check_emulation.sh [iid] [arch] [serial_init_optional]
    exit 1
fi

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

IID=${1}
WORK_DIR=`get_scratch ${IID}`
ARCH=${2}
BRAND="${3:-Unknown}"

# Results belong to this run only.  A failed deep check must not inherit a
# transport-level success marker from an earlier attempt.
rm -f "${WORK_DIR}/ping" "${WORK_DIR}/web" "${WORK_DIR}/web_transport" \
      "${WORK_DIR}/web_acc" "${WORK_DIR}/time_web_acc"

echo "===== Check inferred emulation start ====="
echo "[*] Inferred network: terminating after ${TIMEOUT} secs..."
${WORK_DIR}/run.sh 2>&1 > ${WORK_DIR}/emulation.log &


sleep 70

IPS=()
if (egrep -sq true ${WORK_DIR}/isDhcp); then
  IPS+=("127.0.0.1")
  echo true > ${WORK_DIR}/ping
else
  IP_NUM=`cat ${WORK_DIR}/ip_num`
  for (( IDX=0; IDX<${IP_NUM}; IDX++ ))
  do
    IPS+=(`cat ${WORK_DIR}/ip.${IDX}`)
  done
fi

echo "[*] Waiting web service... from ${IPS[@]}: terminating after ${CHECK_TIMEOUT} secs..."
read IP PING_RESULT WEB_RESULT TIME_PING TIME_WEB < <(check_network "${IPS[@]}" false)

if [ "${PING_RESULT}" = "true" ]; then
    echo true > ${WORK_DIR}/ping
    echo ${TIME_PING} > ${WORK_DIR}/time_ping
    echo ${IP} > ${WORK_DIR}/ip
fi
if [ "${WEB_RESULT}" = "true" ]; then
    echo true > ${WORK_DIR}/web_transport
    echo ${TIME_WEB} > ${WORK_DIR}/time_web
fi

if (${WEB_RESULT}); then
    echo "[*] Ping & web check passed, running deep HTTP content check..."

    WEB_OK=false
    MAX_ROUNDS=3
    SLEEP_SECS=15
    for round in $(seq 1 ${MAX_ROUNDS}); do
        echo "[*] Deep HTTP check round ${round}/${MAX_ROUNDS} ..."
        rm -f "${WORK_DIR}/web_acc" "${WORK_DIR}/time_web_acc"
        python3 "${SCRIPT_DIR}/http_check.py" "${BRAND}" "${WORK_DIR}" || true
        if [ -f "${WORK_DIR}/web_acc" ]; then
            echo "[+] web_acc found -> deep web check SUCCESS"
            WEB_OK=true
            break
        fi
        if [ "${round}" -lt "${MAX_ROUNDS}" ]; then
            echo "[!] web_acc not found, sleep ${SLEEP_SECS}s then retry..."
            sleep "${SLEEP_SECS}"
        fi
    done
    if [ "${WEB_OK}" = true ]; then
        echo "[*] Deep web check passed."
        echo true > "${WORK_DIR}/web"
        if [ -f "${WORK_DIR}/time_web_acc" ]; then
            cp "${WORK_DIR}/time_web_acc" "${WORK_DIR}/time_web"
        fi
        if [ -f "${WORK_DIR}/runtime_state.json" ]; then
            python3 "${SCRIPT_DIR}/collect_web_resources.py" \
                --work-dir "${WORK_DIR}" --workers 4 --limit 2000 || true
            if [ -f "${WORK_DIR}/web_resources/manifest.json" ]; then
                python3 "${SCRIPT_DIR}/export_deepfw_dataset.py" \
                    --manifest "${WORK_DIR}/web_resources/manifest.json" \
                    --output-root "${FIRMWELD_DIR}/deepfw_dataset" || true
            fi
        fi
    else
        echo "[!] Deep web check FAILED after ${MAX_ROUNDS} rounds (no web_acc)."
        rm -f "${WORK_DIR}/web"
    fi
fi

kill $(ps aux | grep `get_qemu ${ARCH}` | grep -v grep | awk '{print $2}') | true

echo "=====  Check inferred emulation end  ====="

sleep 2
