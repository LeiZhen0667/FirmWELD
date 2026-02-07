#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
BINARY=`${BUSYBOX} cat /firmadyne/service`
BINARY_NAME=`${BUSYBOX} basename ${BINARY}`

if (${FIRMWELD_ETC}); then
    if [ "$BINARY" = "/etc/init.d/uhttpd start" ]; then
        /sbin/ubusd &
        ${BUSYBOX} sleep 3

        $BINARY &
        
        while true; do
            ${BUSYBOX} sleep 10
            
            if ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi "uhttpd"); then
                echo "[run.sh] uhttpd not running, restarting ubusd and uhttpd..." >&2
                /sbin/ubusd &
                ${BUSYBOX} sleep 3
                $BINARY &
            else
                echo "[run.sh] uhttpd is running, checking every 30 seconds..." >&2
                ${BUSYBOX} sleep 10
            fi
        done
    else
        
        $BINARY &
        ${BUSYBOX} sleep 10
        while true; do
            ${BUSYBOX} sleep 10
            if ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi ${BINARY_NAME}); then
                $BINARY &
            fi
        done
    fi
fi