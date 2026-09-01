#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
SERVICE_CMD=`${BUSYBOX} cat /firmadyne/service`
set -- ${SERVICE_CMD}
SERVICE_PATH="$1"
BINARY_NAME=`${BUSYBOX} basename "${SERVICE_PATH}"`

if (${FIRMWELD_ETC}); then
    if [ -s /firmadyne/ipc_plan ]; then
        while IFS= read -r IPC_CMD; do
            [ -z "${IPC_CMD}" ] && continue
            /firmadyne/sh -c "${IPC_CMD}"
            ${BUSYBOX} sleep 1
        done < /firmadyne/ipc_plan
    fi

    /firmadyne/sh -c "${SERVICE_CMD}" &
    ${BUSYBOX} sleep 10
    while true; do
        ${BUSYBOX} sleep 10
        if ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi "${BINARY_NAME}"); then
            /firmadyne/sh -c "${SERVICE_CMD}" &
        fi
    done
fi
