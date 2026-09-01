#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
IPTABLES=`${BUSYBOX} which iptables 2>/dev/null`

[ -n "${IPTABLES}" ] || exit 0
[ -s /firmadyne/web_ports ] || exit 0

RULES=`${IPTABLES} -S INPUT 2>/dev/null`
echo "${RULES}" | ${BUSYBOX} grep -Eq '(^-P INPUT DROP| -j (DROP|REJECT))' || exit 0

for PORT in `${BUSYBOX} cat /firmadyne/web_ports`; do
    case "${PORT}" in
        ''|*[!0-9]*) continue ;;
    esac
    if ! ${IPTABLES} -C INPUT -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null; then
        ${IPTABLES} -I INPUT 1 -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null || true
    fi
done
