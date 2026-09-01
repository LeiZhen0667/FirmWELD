#!/firmadyne/sh

BUSYBOX=/firmadyne/busybox
export PATH=/firmadyne/wrapper-bin:/sbin:/usr/sbin:/bin:/usr/bin

[ -d /dev ] || mkdir -p /dev
[ -d /root ] || mkdir -p /root
[ -d /sys ] || mkdir -p /sys
[ -d /proc ] || mkdir -p /proc
[ -d /tmp ] || mkdir -p /tmp
mkdir -p /var/lock

${BUSYBOX} mount -t sysfs sysfs /sys
${BUSYBOX} mount -t proc proc /proc
${BUSYBOX} ln -sf /proc/mounts /etc/mtab

mkdir -p /dev/pts
${BUSYBOX} mount -t devpts devpts /dev/pts
${BUSYBOX} mount -t tmpfs tmpfs /run
