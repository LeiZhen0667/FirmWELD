#!/usr/bin/env python3

import sys
import getopt
import re
import struct
import socket
import stat
import os
import time
import subprocess
import pwn
import shutil
import signal

debug = 0
SCRATCHDIR = ''
SCRIPTDIR = ''

QEMUCMDTEMPLATE = """#!/bin/bash

set -e
set -u

ARCHEND=%(ARCHEND)s
IID=%(IID)i

if [ -e ./firmweld.config ]; then
    source ./firmweld.config
elif [ -e ../firmweld.config ]; then
    source ../firmweld.config
elif [ -e ../../firmweld.config ]; then
    source ../../firmweld.config
else
    echo "Error: Could not find 'firmweld.config'!"
    exit 1
fi

RUN_MODE=`basename ${0}`

IMAGE=`get_fs ${IID}`
if (echo ${ARCHEND} | grep -q "mips" && echo ${RUN_MODE} | grep -q "debug"); then
    KERNEL=`get_kernel ${ARCHEND} true`
else
    KERNEL=`get_kernel ${ARCHEND} false`
fi

if (echo ${RUN_MODE} | grep -q "analyze"); then
    QEMU_DEBUG="user_debug=31 firmadyne.syscall=32"
else
    QEMU_DEBUG="user_debug=0 firmadyne.syscall=1"
fi

if (echo ${RUN_MODE} | grep -q "boot"); then
    QEMU_BOOT="-s -S"
else
    QEMU_BOOT=""
fi

QEMU=`get_qemu ${ARCHEND}`
QEMU_MACHINE=`get_qemu_machine ${ARCHEND}`
QEMU_ROOTFS=`get_qemu_disk ${ARCHEND}`
WORK_DIR=`get_scratch ${IID}`

# === 每轮 run.sh 创建唯一标记 ===
RUN_TAG="${RANDOM}.$(date +%%s).$$"
RUN_TAG_FILE="${WORK_DIR}/serial_helper.id"
echo "${RUN_TAG}" > "${RUN_TAG_FILE}"

# === 串口后台 helper ===
(
    TAG="${RUN_TAG}"
    TAG_FILE="${RUN_TAG_FILE}"
    SERIAL="/tmp/qemu.${IID}.S1"
    CFG_LIST="${WORK_DIR}/second_stage_netfix.list"

    # --- 工具函数：检查当前 TAG 是否仍有效 ---
    check_tag() {
        [ -f "${TAG_FILE}" ] || return 1
        [ "$(cat "${TAG_FILE}" 2>/dev/null)" = "${TAG}" ] || return 1
    }

    # --- 工具函数：等待 n 秒，同时检查 TAG ---
    wait_seconds() {
        local secs="$1"
        local i=0
        while [ $i -lt $secs ]; do
            check_tag || return 1
            sleep 1
            i=$((i+1))
        done
    }

    # --- 工具函数：等待串口文件出现（视为 QEMU 启动完成） ---
    wait_serial() {
        local timeout="$1"
        local i=0
        while [ $i -lt $timeout ]; do
            check_tag || return 1
            [ -S "${SERIAL}" ] && return 0
            sleep 1
            i=$((i+1))
        done
        return 1
    }

    # ============================================================
    # 1. 等待 QEMU 串口出现
    # ============================================================
    echo "[run.sh][tag=${TAG}] waiting for serial..." >&2
    if ! wait_serial 300; then
        echo "[run.sh][tag=${TAG}] serial not ready, helper exit." >&2
        exit 0
    fi
    echo "[run.sh][tag=${TAG}] serial detected." >&2

    # ============================================================
    # 2. 从串口出现起，再等 60 秒
    # ============================================================
    echo "[run.sh][tag=${TAG}] waiting 60s before cfg_cmds..." >&2
    if ! wait_seconds 60; then
        echo "[run.sh][tag=${TAG}] wait 60s failed, exit." >&2
        exit 0
    fi

    # ============================================================
    # 任务 1：mount /proc
    # ============================================================
    echo "[run.sh][tag=${TAG}] executing mount /proc..." >&2
    sudo chmod a+rw "${SERIAL}" 2>/dev/null || true
    printf "%%s\n" "mount -t proc proc /proc" | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true
    sleep 3
    echo "[run.sh][tag=${TAG}] mount /proc done." >&2

    # ============================================================
    # 任务 2：执行 run_service.sh（仅当 SERVICE_CMD 非空），去掉了sleep 60
    # ============================================================

    %(SERVICE_BLOCK)s

    # ============================================================
    # 任务 3：cfg_cmds
    # ============================================================
    if [ -f "${CFG_LIST}" ]; then
        echo "[run.sh][tag=${TAG}] executing cfg_cmds..." >&2
        sudo chmod a+rw "${SERIAL}" 2>/dev/null || true

        while IFS= read -r line; do
            [ -z "${line}" ] && continue
            check_tag || exit 0

            # 执行命令，但不打印具体命令内容
            printf "%%s\n" "${line}" | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true
            sleep 1
        done < "${CFG_LIST}"

        echo "[run.sh][tag=${TAG}] cfg_cmds done." >&2
    else
        echo "[run.sh][tag=${TAG}] cfg_cmds skipped (file missing)." >&2
    fi

    # ============================================================
    # 任务 4：循环禁用防火墙（持续运行，直到 TAG 改变），去掉了sleep 60
    # ============================================================
    echo "[run.sh][tag=${TAG}] starting firewall-disable once..." >&2

    check_tag || {
        echo "[run.sh][tag=${TAG}] tag changed, firewall disable skipped." >&2
        exit 0
    }
    printf "chmod +x /firmadyne/network.sh\n" | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true
    printf "/firmadyne/network.sh &\n"        | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true

    echo "[run.sh][tag=${TAG}] firewall disable script started." >&2

) &

DEVICE=`add_partition "${WORK_DIR}/image.raw"`
mount ${DEVICE} ${WORK_DIR}/image > /dev/null

echo "%(NETWORK_TYPE)s" > ${WORK_DIR}/image/firmadyne/network_type
echo "%(NET_BRIDGE)s" > ${WORK_DIR}/image/firmadyne/net_bridge
echo "%(NET_INTERFACE)s" > ${WORK_DIR}/image/firmadyne/net_interface

echo "#!/firmadyne/sh" > ${WORK_DIR}/image/firmadyne/debug.sh
if (echo ${RUN_MODE} | grep -q "debug"); then
    echo "while (true); do /firmadyne/busybox nc -lp 31337 -e /firmadyne/sh; done &" >> ${WORK_DIR}/image/firmadyne/debug.sh
    echo "/firmadyne/busybox telnetd -p 31338 -l /firmadyne/sh" >> ${WORK_DIR}/image/firmadyne/debug.sh
fi
chmod a+x ${WORK_DIR}/image/firmadyne/debug.sh

sleep 1
sync
umount ${WORK_DIR}/image > /dev/null
del_partition ${DEVICE:0:$((${#DEVICE}-2))}

%(START_NET)s


echo -n "Starting emulation of firmware... "
%(QEMU_ENV_VARS)s ${QEMU} ${QEMU_BOOT} -m 1024 -M ${QEMU_MACHINE} -kernel ${KERNEL} \\
    %(QEMU_DISK)s -append "root=${QEMU_ROOTFS} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 %(QEMU_INIT)s rw debug ignore_loglevel print-fatal-signals=1 FIRMWELD_NET=${FIRMWELD_NET} FIRMWELD_NVRAM=${FIRMWELD_NVRAM} FIRMWELD_KERNEL=${FIRMWELD_KERNEL} FIRMWELD_ETC=${FIRMWELD_ETC} ${QEMU_DEBUG}" \\
    -serial file:${WORK_DIR}/qemu.final.serial.log \\
    -serial unix:/tmp/qemu.${IID}.S1,server,nowait \\
    -monitor unix:/tmp/qemu.${IID},server,nowait \\
    -display none \\
    %(QEMU_NETWORK)s | true

%(STOP_NET)s

echo "Done!"
"""


def mountImage(targetDir):
    loopFile = subprocess.check_output(
        ['bash', '-c', 'source firmweld.config && add_partition %s/image.raw' % targetDir]).decode().strip()
    os.system('mount %s %s/image > /dev/null' % (loopFile, targetDir))
    time.sleep(1)
    return loopFile


def umountImage(targetDir, loopFile):
    os.system('umount %s/image > /dev/null' % targetDir)
    subprocess.check_output(['bash', '-c', 'source firmweld.config && del_partition %s' % loopFile.rsplit('p', 1)[0]])


def checkVariable(key):
    if os.environ[key] == 'true':
        return True
    else:
        return False


def stripTimestamps(data):
    lines = data.split(b"\n")
    # throw out the timestamps
    prog = re.compile(b"^\[[^\]]*\] firmadyne: ")
    lines = [prog.sub(b"", l) for l in lines]
    return lines

def _has_valid_ip(ip_bytes):

    if not ip_bytes:
        return False
    try:
        text = ip_bytes.decode(errors="ignore")
    except Exception:
        return False

    ipv4_mask_re = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})\b')
    for ip, mask_s in ipv4_mask_re.findall(text):
        parts = ip.split(".")
        if len(parts) != 4:
            continue
        try:
            nums = [int(p) for p in parts]
            mask = int(mask_s)
        except ValueError:
            continue

        if any(n < 0 or n > 255 for n in nums):
            continue

        if mask < 0 or mask > 32:
            continue

        # 0.0.0.0/8
        if nums[0] == 0:
            continue
        # loopback 127.0.0.0/8
        if nums[0] == 127:
            continue
        # QEMU：10.0.2.0/24
        if nums[0] == 10 and nums[1] == 0 and nums[2] == 2:
            continue
        return True
    return False

def findMacChanges(data, endianness, mode="serial", ip_data=None):
    
    def _from_serial_log(log_data, endianness):

        lines = stripTimestamps(log_data)
        candidates = filter(lambda l: l.startswith(b"ioctl_SIOCSIFHWADDR"), lines)
        if debug:
            print("Mac Changes %r" % candidates)

        result = []
        if endianness == "eb":
            fmt = ">I"
        elif endianness == "el":
            fmt = "<I"
        else:
            fmt = "<I"  

        prog = re.compile(
            b"^ioctl_SIOCSIFHWADDR\\[[^\\]]+\\]: dev:([^ ]+) mac:0x([0-9a-f]+) 0x([0-9a-f]+)"
        )
        for c in candidates:
            g = prog.match(c)
            if g:
                (iface, mac0, mac1) = g.groups()
                iface = iface.decode("utf-8", errors="ignore")
                m0 = struct.pack(fmt, int(mac0, 16))[2:]
                m1 = struct.pack(fmt, int(mac1, 16))
                mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", m0 + m1)
                result.append((iface, mac))
        return result

    def _from_ip_addr(ip_text):
        ifaces = _parse_ip_addr(ip_text)
        result = []
        for name, info in ifaces.items():
            if not info.get("state_up"):
                continue
            mac = info.get("mac")
            if mac:
                result.append((name, mac))
        return result

    mode = (mode or "serial").lower()

    if mode == "serial":
        final = _from_serial_log(data, endianness)

    elif mode == "ip_addr":
        final = _from_ip_addr(ip_data)

    elif mode == "union":
        serial_res = _from_serial_log(data, endianness)
        ip_res = _from_ip_addr(ip_data)
        final = serial_res + ip_res

    else:
        raise ValueError('mode must be "serial", "ip_addr", or "union"')

    seen = set()
    deduped = []
    for item in final:
        if item not in seen:
            deduped.append(item)
            seen.add(item)

    return deduped


def findPorts(data, endianness):
    lines = stripTimestamps(data)
    candidates = filter(lambda l: l.startswith(b"inet_bind"), lines)  # logs for the inconfig process
    result = []
    if endianness == "eb":
        fmt = ">I"
    elif endianness == "el":
        fmt = "<I"
    prog = re.compile(b"^inet_bind\[[^\]]+\]: proto:SOCK_(DGRAM|STREAM), ip:port: 0x([0-9a-f]+):([0-9]+)")
    portSet = {}
    for c in candidates:
        g = prog.match(c)
        if g:
            (proto, addr, port) = g.groups()
            proto = "tcp" if proto == b"STREAM" else "udp"
            addr = socket.inet_ntoa(struct.pack(fmt, int(addr, 16)))
            port = int(port.decode())
            if port not in portSet:
                result.append((proto, addr, port))
                portSet[port] = True
    return result


def findNonLoInterfaces(data, endianness, mode="serial", ip_data=None):

    def _from_serial_log(log_data, endianness):
        lines = stripTimestamps(log_data)
        candidates = filter(lambda l: l.startswith(b"__inet_insert_ifa"), lines)
        if debug:
            print("Candidate ifaces: %r" % candidates)

        result = []
        if endianness == "eb":
            fmt = ">I"
        elif endianness == "el":
            fmt = "<I"
        else:
            fmt = "<I"  

        prog = re.compile(b"^__inet_insert_ifa\\[[^\\]]+\\]: device:([^ ]+) ifa:0x([0-9a-f]+)")
        for c in candidates:
            g = prog.match(c)
            if g:
                (iface, addr) = g.groups()
                iface = iface.decode('utf-8', errors='ignore')
                addr = socket.inet_ntoa(struct.pack(fmt, int(addr, 16)))

                if addr != "127.0.0.1" and addr != "0.0.0.0":
                    result.append((iface, addr))
        return result

    def _from_ip_addr(ip_text):
        ifaces = _parse_ip_addr(ip_text)
        result = []
        for name, info in ifaces.items():
            if not info.get("state_up"):
                continue
            for ip in info.get("ips4", []):
                if ip != "127.0.0.1" and ip != "0.0.0.0":
                    result.append((name, ip))
        return result

    mode = (mode or "serial").lower()

    if mode == "serial":
        final = _from_serial_log(data, endianness)

    elif mode == "ip_addr":
        final = _from_ip_addr(ip_data)

    elif mode == "union":
        serial_res = _from_serial_log(data, endianness)
        ip_res = _from_ip_addr(ip_data)
        final = serial_res + ip_res

    else:
        raise ValueError('mode must be "serial", "ip", or "union"')

    seen = set()
    deduped = []
    for item in final:
        if item not in seen:
            deduped.append(item)
            seen.add(item)

    return deduped


def findIfacesForBridge(data, brif, mode="serial", ip_data=None):

    mode = (mode or "serial").lower()

    def _from_serial(log_data):
        lines = stripTimestamps(log_data)
        result = []
        candidates = filter(lambda l: l.startswith(b"br_dev_ioctl") or l.startswith(b"br_add_if"), lines)
        progs = [
            re.compile(p % brif.encode())
            for p in [
                b"^br_dev_ioctl\\[[^\\]]+\\]: br:%s dev:(.*)",
                b"^br_add_if\\[[^\\]]+\\]: br:%s dev:(.*)"
            ]
        ]
        for c in candidates:
            for p in progs:
                g = p.match(c)
                if g:
                    iface = g.group(1).decode("utf-8", errors="ignore").strip()
                    if iface != brif:
                        result.append(iface)
        return result

    def _from_ip(ip_text):
        ifaces = _parse_ip_addr(ip_text)
        res = []
        for name, info in ifaces.items():
            if info.get("master") == brif and name != brif:
                if info.get("state_up"):  # <===== 新增
                    res.append(name.strip())
        return res

    if mode == "serial":
        return _from_serial(data)
    elif mode == "ip_addr":
        return _from_ip(ip_data)
    elif mode == "union":
        s = _from_serial(data)
        i = _from_ip(ip_data)
        # 并集去重
        seen, out = set(), []
        for x in s + i:
            if x not in seen:
                out.append(x);
                seen.add(x)
        return out
    else:
        raise ValueError('mode must be "serial", "ip_addr", or "union"')


def findVlanInfoForDev(data, dev, mode="serial", ip_data=None):

    mode = (mode or "serial").lower()

    def _from_serial(log_data):
        lines = stripTimestamps(log_data)
        results = []
        candidates = filter(lambda l: l.startswith(b"register_vlan_dev"), lines)
        prog = re.compile(
            b"register_vlan_dev\\[[^\\]]+\\]: dev:%s vlan_id:([0-9]+)" % dev.encode()
        )
        for c in candidates:
            g = prog.match(c)
            if g:
                results.append(int(g.group(1)))
        return results

    def _from_ip(ip_text):
        ifaces = _parse_ip_addr(ip_text)
        raw = dev.strip()

        vid_self = _infer_vlan_id_from_name(raw)
        if vid_self is not None:
            info = ifaces.get(raw)
            if info and not info.get("state_up"):
                return []
            return [vid_self]

        results = []
        for name, info in ifaces.items():
            if not info.get("state_up"):
                continue

            if info.get("lower") == raw or ("@" in info["raw"] and info["raw"].endswith("@" + raw)):
                vid = _infer_vlan_id_from_name(info["raw"])
                if vid is not None:
                    results.append((vid, 1 if info.get("master") else 0))

        results.sort(key=lambda x: (-x[1], x[0]))
        return [vid for vid, _ in results]

    if mode == "serial":
        return _from_serial(data)
    elif mode == "ip_addr":
        return _from_ip(ip_data)
    elif mode == "union":
        s = _from_serial(data)
        i = _from_ip(ip_data)
        seen, out = set(), []
        for x in s + i:
            if x not in seen:
                out.append(x);
                seen.add(x)
        return out
    else:
        raise ValueError('mode must be "serial", "ip_addr", or "union"')


def ifaceNo(dev):
    g = re.match(r"[^0-9]+([0-9]+)", dev)
    return int(g.group(1)) if g else -1


def isDhcpIp(ip):
    # normal dhcp client ip
    if ip.startswith("10.0.2."):
        return True
    # netgear armel R6900 series
    elif ip.endswith(".190"):
        return True
    return False


def qemuArchNetworkConfig(i, tap_num, arch, n, isUserNetwork, ports):
    if arch == "arm":
        device = "virtio-net-device"
    else:
        device = "e1000"

    if not n:
        return "-device %(DEVICE)s,netdev=net%(I)i -netdev socket,id=net%(I)i,listen=:200%(I)i" % {'DEVICE': device,
                                                                                                   'I': i}
    else:
        (ip, dev, vlan, mac, brif) = n
        vlan_id = vlan if vlan else i
        mac_str = "" if not mac else ",macaddr=%s" % mac
        if isUserNetwork:  # user network dhcp server
            portfwd = "hostfwd=tcp::80-:80,hostfwd=tcp::443-:443,"
            for (proto, ip, port) in ports:
                if port in [80, 443]:
                    continue
                portfwd += "hostfwd=%(TYPE)s::%(PORT)i-:%(PORT)i," % {"TYPE": proto, "PORT": port}

            return "-device %(DEVICE)s,netdev=net%(I)i -netdev user,id=net%(I)i,%(FWD)s" % {'DEVICE': device, 'I': i,
                                                                                            "FWD": portfwd[:-1]}
        else:
            return "-device %(DEVICE)s,netdev=net%(I)i -netdev tap,id=net%(I)i,ifname=${TAPDEV_%(TAP_NUM)i},script=no" % {
                'I': i, 'DEVICE': device, 'TAP_NUM': tap_num}


def qemuNetworkConfig(arch, network, isUserNetwork, ports):
    output = []
    assigned = []
    interfaceNum = 4
    if arch == "arm" and checkVariable("FIRMWELD_NET"):
        interfaceNum = 1

    for i in range(0, interfaceNum):
        for j, n in enumerate(network):
            # need to connect the jth emulated network interface to the corresponding host interface
            if i == ifaceNo(n[1]):
                output.append(qemuArchNetworkConfig(i, j, arch, n, isUserNetwork, ports))
                assigned.append(n)
                break

        # otherwise, put placeholder socket connection
        if len(output) <= i:
            output.append(qemuArchNetworkConfig(i, i, arch, None, isUserNetwork, ports))

    # find unassigned interfaces
    for j, n in enumerate(network[:interfaceNum]):
        if n not in assigned:
            # guess assignment
            print("Warning: Unmatched interface: %s" % (n,))
            output[j] = qemuArchNetworkConfig(j, j, arch, n, isUserNetwork, ports)
            assigned.append(n)

    return ' '.join(output)


def buildConfig(brif, iface, vlans, macs):
    ip = brif[1]
    br = brif[0]

    # iface： vlan1@eth2 / eth2.1 / eth2
    if "@" in iface:
        # vlan1@eth2 -> eth2
        dev = iface.split("@", 1)[1]
    else:
        dev = iface.split(".", 1)[0]

    mac = None
    d = dict(macs)
    if br in d:
        mac = d[br]
    elif dev in d:
        mac = d[dev]

    vlan_id = vlans[0] if vlans else None
    return (ip, dev, vlan_id, mac, br)


def convertToHostIp(ip):
    tups = [int(x) for x in ip.split(".")]
    if tups[3] > 1:  # sometimes it can has 0 asus FW_RT_AC3100_300438432738
        tups[3] -= 1
    else:
        tups[3] += 1
    return ".".join([str(x) for x in tups])


# iterating the networks
def startNetwork(network):
    template_1 = """
TAPDEV_%(I)i=tap${IID}_%(I)i
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}
echo "Creating TAP device ${TAPDEV_%(I)i}..."
sudo tunctl -t ${TAPDEV_%(I)i} -u ${USER}
"""

    if checkVariable("FIRMWELD_NET"):
        template_vlan = """
echo "Initializing VLAN..."
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}.%(VLANID)i
sudo ip link add link ${TAPDEV_%(I)i} name ${HOSTNETDEV_%(I)i} type vlan id %(VLANID)i
sudo ip link set ${TAPDEV_%(I)i} up
"""

        template_2 = """
echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_%(I)i} up
sudo ip addr add %(HOSTIP)s/24 dev ${HOSTNETDEV_%(I)i}
"""
    else:
        template_vlan = """
echo "Initializing VLAN..."
HOSTNETDEV_%(I)i=${TAPDEV_%(I)i}.%(VLANID)i
sudo ip link add link ${TAPDEV_%(I)i} name ${HOSTNETDEV_%(I)i} type vlan id %(VLANID)i
sudo ip link set ${HOSTNETDEV_%(I)i} up
"""

        template_2 = """
echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_%(I)i} up
sudo ip addr add %(HOSTIP)s/24 dev ${HOSTNETDEV_%(I)i}

echo "Adding route to %(GUESTIP)s..."
sudo ip route add %(GUESTIP)s via %(GUESTIP)s dev ${HOSTNETDEV_%(I)i}
"""

    output = []
    for i, (ip, dev, vlan, mac, brif) in enumerate(network):
        output.append(template_1 % {'I': i})
        if vlan != None:
            output.append(template_vlan % {'I': i, 'VLANID': vlan})
        output.append(template_2 % {'I': i, 'HOSTIP': convertToHostIp(ip), 'GUESTIP': ip})
    return '\n'.join(output)


def stopNetwork(network):
    template_1 = """
echo "Bringing down TAP device..."
sudo ip link set ${TAPDEV_%(I)i} down
"""

    template_vlan = """
echo "Removing VLAN..."
sudo ip link delete ${HOSTNETDEV_%(I)i}
"""

    template_2 = """
echo "Deleting TAP device ${TAPDEV_%(I)i}..."
sudo tunctl -d ${TAPDEV_%(I)i}
"""

    output = []
    for i, (ip, dev, vlan, mac, brif) in enumerate(network):
        output.append(template_1 % {'I': i})
        if vlan != None:
            output.append(template_vlan % {'I': i})
        output.append(template_2 % {'I': i})
    return '\n'.join(output)


def _parse_ip_addr(ip_text):

    if not ip_text:
        return {}

    if isinstance(ip_text, bytes):
        text = ip_text.decode("utf-8", errors="ignore")
    else:
        text = str(ip_text)

    lines = text.splitlines()

    hdr_re = re.compile(r'^\s*\d+:\s+([^:]+):\s*<([^>]*)>\s*(.*)$')
    mac_re = re.compile(r'^\s*link/(?:ether|loopback)\s+([0-9a-fA-F:]{17})\b')
    inet4_re = re.compile(r'^\s*inet\s+(\d+\.\d+\.\d+\.\d+)/\d+\b')

    ifaces = {}
    cur = None

    for line in lines:
        m = hdr_re.match(line)
        if m:
            name = m.group(1).strip()
            flags = (m.group(2) or "").upper()
            flag_list = [x.strip().upper() for x in flags.split(",")]
            tail = m.group(3) or ""

            master = None
            mm = re.search(r'\bmaster\s+([^\s]+)', tail)
            if mm:
                master = mm.group(1)

            lower = None
            if '@' in name:
                lower = name.split('@', 1)[1]

            state_up = (("LOWER_UP" in flag_list) or bool(re.search(r'\bstate\s+UP\b', tail, re.I)))

            ifaces[name] = {
                "raw": name,
                "name": name,
                "master": master,
                "lower": lower,
                "mac": None,
                "ips4": [],
                "state_up": state_up,
            }
            cur = name
            continue

        if cur is None:
            continue

        mmac = mac_re.match(line)
        if mmac:
            ifaces[cur]["mac"] = mmac.group(1).lower()
            continue

        mip = inet4_re.match(line)
        if mip:
            ifaces[cur]["ips4"].append(mip.group(1))
            continue

    for k, v in ifaces.items():
        if v["lower"] is None and "." in v["raw"]:
            v["lower"] = v["raw"].split(".", 1)[0]

    return ifaces


def _infer_vlan_id_from_name(ifname):

    if not ifname:
        return None

    name = ifname.strip()

    # ---------- 1) dot VLAN: <base>.<vid> 或 <base>.<vid>@<lower> ----------
    # e.g. eth0.1, eth0.1@eth0, br0.10@br0, lan1.100
    m = re.match(r'^[^@\s]+\.(\d+)(?:@[^@\s]+)?$', name)
    if m:
        return int(m.group(1))

    # ---------- 2) "vlanN" / "vlanN@xxx" ----------
    m = re.match(r'^vlan(?:-)?(\d+)(?:@.+)?$', name, re.I)
    if m:
        return int(m.group(1))

    return None


def qemuCmd(iid, network, ports, network_type, arch, endianness, qemuInitValue, isUserNetwork, service_cmd=""):
    network_bridge = ""
    network_iface = ""
    if arch == "mips":
        qemuEnvVars = ""
        qemuDisk = "-drive if=ide,format=raw,file=${IMAGE}"
        if endianness != "eb" and endianness != "el":
            raise Exception("You didn't specify a valid endianness")
    elif arch == "arm":
        qemuDisk = "-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
        if endianness == "el":
            qemuEnvVars = "QEMU_AUDIO_DRV=none"
        elif endianness == "eb":
            raise Exception("armeb currently not supported")
        else:
            raise Exception("You didn't specify a valid endianness")
    else:
        raise Exception("Unsupported architecture")

    for (ip, dev, vlan, mac, brif) in network:
        network_bridge = brif
        network_iface = dev
        break

    if service_cmd:
        SERVICE_BLOCK = r"""
        echo "[run.sh][tag=${TAG}] starting service run_service.sh..." >&2

        check_tag || {
            echo "[run.sh][tag=${TAG}] tag changed, service skipped." >&2
            exit 0
        }
        printf "chmod +x /firmadyne/run_service.sh\n" | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true
        printf "/firmadyne/run_service.sh &\n" | socat - "UNIX-CLIENT:${SERIAL}" 2>/dev/null || true

        echo "[run.sh][tag=${TAG}] run_service.sh started." >&2
        sleep 3
        """
    else:
        SERVICE_BLOCK = ""

    return QEMUCMDTEMPLATE % {'IID': iid,
                              'NETWORK_TYPE': network_type,
                              'NET_BRIDGE': network_bridge,
                              'NET_INTERFACE': network_iface,
                              'START_NET': startNetwork(network),
                              'STOP_NET': stopNetwork(network),
                              'ARCHEND': arch + endianness,
                              'QEMU_DISK': qemuDisk,
                              'QEMU_INIT': qemuInitValue,
                              'QEMU_NETWORK': qemuNetworkConfig(arch, network, isUserNetwork, ports),
                              'QEMU_ENV_VARS': qemuEnvVars,
                              'SERVICE_BLOCK': SERVICE_BLOCK
                              }


def getNetworkList(data, ifacesWithIps, macChanges, mode="serial", ip_data=None):

    global debug
    mode = (mode or "serial").lower()

    
    def _is_valid_ip(ip):
        if not ip:
            return False
       
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            nums = [int(x) for x in parts]
        except ValueError:
            return False
        
        if any(n < 0 or n > 255 for n in nums):
            return False
        
        if ip == "0.0.0.0":
            return False
        # loopback
        if nums[0] == 127:
            return False
        # QEMU 10.0.2.0/24
        if nums[0] == 10 and nums[1] == 0 and nums[2] == 2:
            return False
        # link-local 169.254.0.0/16
        if nums[0] == 169 and nums[1] == 254:
            return False
        return True

    def _pick_mac(mac_map, br, dev):
        return mac_map.get(br) or mac_map.get(dev)

    def _build_legacy_ifaces(ifacesWithIps_local, data_local):

        ifaces_map = {}

        for iwi in ifacesWithIps_local:
            name = iwi[0]
            if name == "lo":
                continue
            if name not in ifaces_map:
                ifaces_map[name] = {
                    "name": name,
                    "mac": None,
                    "ips4": [],
                    "master": None,
                    "lower": None,
                    "state_up": False,
                }

        try:
            bridges = [n for n in ifaces_map.keys() if n.startswith("br")]
            for br in bridges:
                try:
                    members = findIfacesForBridge(data_local, br, mode="serial", ip_data=None) or []
                except Exception:
                    members = []
                for dev in members:
                    if dev in ifaces_map:
                        ifaces_map[dev]["master"] = br
        except Exception:

            if debug:
                print("[WARN] _build_legacy_ifaces: failed to infer masters")

        return ifaces_map

    def _ensure_default_bridge(ifaces_map, mac_map, networkList_out, cfg_cmds_out,
                           default_ip="192.168.0.1"):

        if networkList_out:
            return

        bridges = [
            n for n, info in ifaces_map.items()
            if n.startswith("br") or any(i.get("master") == n for i in ifaces_map.values())
        ]
        bridges.sort()

        if bridges:
            br = bridges[0]
            need_create_bridge = False
        else:
            br = "br0"
            need_create_bridge = True  

        ip = default_ip

        if need_create_bridge:
            cfg_cmds_out.append(
                f"/firmadyne/busybox brctl addbr {br}'"
            )

        cfg_cmds_out.append(f"/firmadyne/busybox ip link set {br} up")
        cfg_cmds_out.append(f"/firmadyne/busybox ip addr add {ip}/24 dev {br}")

        eths = [(n, info) for n, info in ifaces_map.items() if n.startswith("eth")]
        eths.sort(key=lambda x: ifaceNo(x[0]))

        if eths:
            for name, inf in eths:
                old_master = inf.get("master")
                if old_master and old_master != br:
                    cfg_cmds_out.append(f"/firmadyne/busybox brctl delif {old_master} {name}")

                if not inf.get("state_up"):
                    cfg_cmds_out.append(f"/firmadyne/busybox ip link set {name} up")

                cfg_cmds_out.append(f"/firmadyne/busybox brctl addif {br} {name}")

                mac = _pick_mac(mac_map, br, name)
                networkList_out.append((ip, name, None, mac, br))
                break
        else:
            mac = _pick_mac(mac_map, br, br)
            networkList_out.append((ip, br, None, mac, br))

    # =========================
    # 1) serial
    # =========================
    def _core_build(ifacesWithIps_local, macChanges_local, find_bridge_fn, find_vlan_fn):
        networkList_local = []
        deviceHasBridge = False

        for iwi in ifacesWithIps_local:
            if iwi[0] == 'lo':
                continue

            brifs = find_bridge_fn(iwi[0])
            if debug:
                print("brifs for %s %r" % (iwi[0], brifs))

            for dev in brifs:
                vlans = find_vlan_fn(dev)
                config = buildConfig(iwi, dev, vlans, macChanges_local)
                if config not in networkList_local:
                    networkList_local.append(config)
                    deviceHasBridge = True

            if not brifs and not deviceHasBridge:
                vlans = find_vlan_fn(iwi[0])
                config = buildConfig(iwi, iwi[0], vlans, macChanges_local)
                if config not in networkList_local:
                    networkList_local.append(config)

        return networkList_local

    def _serial_network():
        return _core_build(
            ifacesWithIps,
            macChanges,
            find_bridge_fn=lambda br: findIfacesForBridge(
                data, br, mode="serial", ip_data=ip_data
            ),
            find_vlan_fn=lambda dev: findVlanInfoForDev(
                data, dev, mode="serial", ip_data=ip_data
            ),
        )

    def _ip_network_legacy():

        return _core_build(
            ifacesWithIps,
            macChanges,
            find_bridge_fn=lambda br: findIfacesForBridge(
                data, br, mode="ip_addr", ip_data=ip_data
            ),
            find_vlan_fn=lambda dev: findVlanInfoForDev(
                data, dev, mode="ip_addr", ip_data=ip_data
            ),
        )

    if mode != "ip_addr":
        
        if mode == "serial":
            networkList = _serial_network()
        elif mode == "union":
            s = _serial_network()
            i = _ip_network_legacy()
            seen, networkList = set(), []
            for x in s + i:
                if x not in seen:
                    networkList.append(x)
                    seen.add(x)
        elif mode == "ip_addr":  
            networkList = _ip_network_legacy()
        else:
            raise ValueError('mode must be "serial", "ip_addr", or "union"')

        if checkVariable("FIRMWELD_NET"):
            return networkList
        else:
            ips = set()
            pruned_network = []
            for n in networkList:
                if n[0] not in ips:
                    ips.add(n[0])
                    pruned_network.append(n)
                else:
                    if debug:
                        print("duplicate ip address for interface: ", n)
            return pruned_network

    mac_map = dict(macChanges)
    cfg_cmds = []
    networkList = []

    if not ip_data:
        br = "br0"
        eth_name = "eth0"
        eth_ip = "192.168.0.1"

        cfg_cmds.append(f"/firmadyne/busybox ip link set {br} up")
        cfg_cmds.append(f"/firmadyne/busybox ip addr add {eth_ip}/24 dev {br}")
        cfg_cmds.append(f"/firmadyne/busybox ip addr flush dev {eth_name}")
        cfg_cmds.append(f"/firmadyne/busybox ip link set {eth_name} up")
        cfg_cmds.append(f"/firmadyne/busybox brctl addif {br} {eth_name}")

        networkList.append((eth_ip, eth_name, None, None, br))

        if not checkVariable("FIRMWELD_NET"):
            ips = set()
            pruned_network = []
            for n in networkList:
                if n[0] not in ips:
                    ips.add(n[0])
                    pruned_network.append(n)
                else:
                    if debug:
                        print("duplicate ip address for interface: ", n)
            networkList = pruned_network

        return networkList, cfg_cmds

    try:
        ifaces = _parse_ip_addr(ip_data)
    except Exception as e:
        if debug:
            print("[WARN] _parse_ip_addr failed:", e)
        ifaces = None

    if not ifaces:
        ifaces_fallback = _build_legacy_ifaces(ifacesWithIps, data)
        _ensure_default_bridge(ifaces_fallback, mac_map, networkList, cfg_cmds)

        if not checkVariable("FIRMWELD_NET"):
            ips = set()
            pruned_network = []
            for n in networkList:
                if n[0] not in ips:
                    ips.add(n[0])
                    pruned_network.append(n)
            networkList = pruned_network

        return networkList, cfg_cmds

    used_bases = set()
    base_owner_bridge = {}

    def _base_in_use(base):
        return base in used_bases

    def _mark_base_used(base, br):
        used_bases.add(base)
        base_owner_bridge[base] = br

    bridges_with_ip = []
    for name, info in ifaces.items():
        ips4 = info.get("ips4", []) or []
        ips = [ip for ip in ips4 if _is_valid_ip(ip)]
        if not ips:
            continue

        is_bridge = name.startswith("br") or any(
            i.get("master") == name for i in ifaces.values()
        )
        if not is_bridge:
            continue

        bridges_with_ip.append((name, ips[0], bool(info.get("state_up"))))  # (br, ip, is_up)

    bridges_with_ip.sort(key=lambda x: x[0])
    up_bridges = [(br, ip, up) for (br, ip, up) in bridges_with_ip if up]
    if up_bridges:
        bridges_with_ip = up_bridges

    for br, ip, _br_up in bridges_with_ip:
        br_info = ifaces.get(br, {})
        if debug:
            print("br_info:", br_info)

        if not br_info.get("state_up"):
            cfg_cmds.append(f"/firmadyne/busybox ip link set {br} up")

        members = [
            (n, inf) for n, inf in ifaces.items()
            if inf.get("master") == br and n != br
        ]
        if debug:
            print("members:", members)

        vlan_members = []
        eth_members = []

        for n, inf in members:
            vid = _infer_vlan_id_from_name(n)
            lower = inf.get("lower")
            base = lower or n.split("@", 1)[0].split(".", 1)[0]
            if not base.startswith("eth"):
                continue

            if _base_in_use(base) and base_owner_bridge.get(base) != br:
                continue

            if vid is not None:
                vlan_members.append((n, base, vid, inf))
            else:
                eth_members.append((n, base, None, inf))

        def _handle_vlan_members(vlist):
            vlist_sorted = sorted(vlist, key=lambda x: ifaceNo(x[1]))

            # ① 先找 up 的
            for name, base, vid, inf in vlist_sorted:
                if inf.get("state_up"):
                    base_info = ifaces.get(base)
                    if base_info and not base_info.get("state_up"):
                        cfg_cmds.append(f"/firmadyne/busybox ip link set {base} up")
                    mac = _pick_mac(mac_map, br, base)
                    networkList.append((ip, base, vid, mac, br))
                    _mark_base_used(base, br)
                    return

            name, base, vid, inf = vlist_sorted[0]

            if not inf.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {name} up")

            base_info = ifaces.get(base)
            if base_info and not base_info.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {base} up")

            mac = _pick_mac(mac_map, br, base)
            networkList.append((ip, base, vid, mac, br))
            _mark_base_used(base, br)

        def _handle_eth_members(elist):
            elist_sorted = sorted(elist, key=lambda x: ifaceNo(x[1]))

            for name, base, vid, inf in elist_sorted:
                if inf.get("state_up"):
                    mac = _pick_mac(mac_map, br, base)
                    networkList.append((ip, base, vid, mac, br))
                    _mark_base_used(base, br)
                    return

            name, base, vid, inf = elist_sorted[0]

            if not inf.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {base} up")

            mac = _pick_mac(mac_map, br, base)
            networkList.append((ip, base, vid, mac, br))
            _mark_base_used(base, br)

        def _collect_up_members(vlist, elist):

            added = False

            if vlist:
                for name, base, vid, inf in sorted(vlist, key=lambda x: ifaceNo(x[1])):
                    if not inf.get("state_up"):
                        continue

                    if _base_in_use(base) and base_owner_bridge.get(base) != br:
                        continue


                    base_info = ifaces.get(base)
                    if base_info and not base_info.get("state_up"):
                        cfg_cmds.append(f"/firmadyne/busybox ip link set {base} up")

                    mac = _pick_mac(mac_map, br, base)
                    networkList.append((ip, base, vid, mac, br))
                    _mark_base_used(base, br)
                    added = True


                if added:
                    return True


            if elist:
                for name, base, _vid, inf in sorted(elist, key=lambda x: ifaceNo(x[1])):
                    if not inf.get("state_up"):
                        continue

                    if _base_in_use(base) and base_owner_bridge.get(base) != br:
                        continue

                    mac = _pick_mac(mac_map, br, base)
                    networkList.append((ip, base, None, mac, br))
                    _mark_base_used(base, br)
                    added = True

            return added

        if vlan_members or eth_members:
            if _collect_up_members(vlan_members, eth_members):
                continue

            if vlan_members:
                _handle_vlan_members(vlan_members)
                continue
            if eth_members:
                _handle_eth_members(eth_members)
                continue

        all_vlan = []
        all_eth = []

        for n, inf in ifaces.items():
            vid = _infer_vlan_id_from_name(n)
            lower = inf.get("lower")
            base = lower or n.split("@", 1)[0].split(".", 1)[0]
            if not base.startswith("eth"):
                continue

            if _base_in_use(base) and base_owner_bridge.get(base) != br:
                continue

            if vid is not None:
                all_vlan.append((n, base, vid, inf))
            else:
                all_eth.append((n, base, None, inf))

        up_vlan_all = [x for x in all_vlan if x[3].get("state_up")]
        up_vlan = sorted(up_vlan_all, key=lambda x: ifaceNo(x[1]))[0] if up_vlan_all else None

        down_vlan_all = [x for x in all_vlan if not x[3].get("state_up")]
        down_vlan = sorted(down_vlan_all, key=lambda x: ifaceNo(x[1]))[0] if down_vlan_all else None

        if up_vlan or down_vlan:
            chosen = up_vlan or down_vlan
            name, base, vid, inf = chosen

            if not inf.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {name} up")

            base_info = ifaces.get(base)
            if base_info and not base_info.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {base} up")

            cfg_cmds.append(f"/firmadyne/busybox brctl addif {br} {name}")

            mac = _pick_mac(mac_map, br, base)
            networkList.append((ip, base, vid, mac, br))
            _mark_base_used(base, br)
            continue

        if all_eth:
            up_eth_all = [x for x in all_eth if x[3].get("state_up")]

            if up_eth_all:
                chosen = sorted(up_eth_all, key=lambda x: ifaceNo(x[1]))[0]
            else:
                chosen = sorted(all_eth, key=lambda x: ifaceNo(x[1]))[0]

            name, base, vid, inf = chosen

            old_master = inf.get("master")
            if old_master and old_master != br:
                cfg_cmds.append(f"/firmadyne/busybox brctl delif {old_master} {name}")

            cfg_cmds.append(f"/firmadyne/busybox brctl addif {br} {name}")

            if not inf.get("state_up"):
                cfg_cmds.append(f"/firmadyne/busybox ip link set {name} up")

            mac = _pick_mac(mac_map, br, base)
            networkList.append((ip, base, vid, mac, br))
            _mark_base_used(base, br)
            continue

    if not networkList:
        eth_ip_candidates = []
        for n, inf in ifaces.items():
            ips4 = inf.get("ips4", []) or []
            ips = [ip for ip in ips4 if _is_valid_ip(ip)]
            if not ips:
                continue
            _ip = ips[0]

            if not n.startswith("eth"):
                continue

            eth_ip_candidates.append((n, _ip, inf))

        if eth_ip_candidates:
            eth_ip_candidates.sort(key=lambda x: ifaceNo(x[0]))
            eth_name, eth_ip, eth_inf = eth_ip_candidates[0]

            bridges = [n for n in ifaces.keys() if n.startswith("br")]
            if debug:
                print("found bridges: ", bridges)
            bridges.sort()
            br = bridges[0] if bridges else "br0"

            if br == "br0" and br not in ifaces:
                if debug:
                    print("[!] No bridge found, creating bridge br0.")
                cfg_cmds.append(f"/firmadyne/busybox ip link add name {br} type bridge")

            cfg_cmds.append(f"/firmadyne/busybox ip link set {br} up")
            cfg_cmds.append(f"/firmadyne/busybox ip addr add {eth_ip}/24 dev {br}")
            cfg_cmds.append(f"/firmadyne/busybox ip addr flush dev {eth_name}")
            cfg_cmds.append(f"/firmadyne/busybox ip link set {eth_name} up")
            cfg_cmds.append(f"/firmadyne/busybox brctl addif {br} {eth_name}")

            mac = _pick_mac(mac_map, br, eth_name)
            networkList.append((eth_ip, eth_name, None, mac, br))

    _ensure_default_bridge(ifaces, mac_map, networkList, cfg_cmds)

    if not checkVariable("FIRMWELD_NET"):
        ips = set()
        pruned_network = []
        for n in networkList:
            if n[0] not in ips:
                ips.add(n[0])
                pruned_network.append(n)
            else:
                if debug:
                    print("duplicate ip address for interface: ", n)
        networkList = pruned_network

    return networkList, cfg_cmds


def readWithException(filePath):
    fileData = ''
    with open(filePath, 'rb') as f:
        while True:
            try:
                line = f.readline().decode()
                if not line:
                    break
                fileData += line
            except:
                fileData += ''

    return fileData


def inferNetwork(iid, arch, endianness, init):
    global SCRIPTDIR
    global SCRATCHDIR
    TIMEOUT = int(os.environ['TIMEOUT'])
    targetDir = SCRATCHDIR + '/' + str(iid)

    loopFile = mountImage(targetDir)

    fileType = subprocess.check_output(
        ["file", "-b", "%s/image/%s" % (targetDir, init)]
    ).decode().strip()
    print("[*] Infer test: %s (%s)" % (init, fileType))

    with open(targetDir + '/image/firmadyne/network_type', 'w') as out:
        out.write("None")

    qemuInitValue = 'rdinit=/firmadyne/preInit.sh'
    if os.path.exists(targetDir + '/service'):
        webService = open(targetDir + '/service').read().strip()
    else:
        webService = None
    print("[*] web service: %s" % webService)

    targetFile = ''
    targetData = ''
    out = None
    if not init.endswith('preInit.sh'):  # rcS, preinit
        if fileType.find('ELF') == -1 and fileType.find("symbolic link") == -1:  # maybe script
            targetFile = targetDir + '/image/' + init
            targetData = readWithException(targetFile)
            out = open(targetFile, 'a')
        # netgear R6200
        elif fileType.find('ELF') != -1 or fileType.find("symbolic link") != -1:
            qemuInitValue = qemuInitValue[2:]  # remove 'rd'
            targetFile = targetDir + '/image/firmadyne/preInit.sh'
            targetData = readWithException(targetFile)
            out = open(targetFile, 'a')
            out.write(init + ' &\n')
    else:  # preInit.sh
        targetFile = targetDir + '/image/firmadyne/preInit.sh'
        targetData = readWithException(targetFile)
        out = open(targetFile, 'a')

    if out:
        out.write('\n/firmadyne/network.sh &\n')
        if webService:
            out.write('/firmadyne/run_service.sh &\n')
        out.write('/firmadyne/debug.sh\n')
        # trendnet TEW-828DRU_1.0.7.2, etc...
        out.write('/firmadyne/busybox sleep 36000\n')
        out.close()

    umountImage(targetDir, loopFile)

    print("Running firmware %d: terminating after %d secs..." % (iid, TIMEOUT))

   
    cmd = "timeout --preserve-status --signal SIGINT {0} ".format(TIMEOUT)
    cmd += "{0}/run.{1}.sh \"{2}\" \"{3}\" ".format(
        SCRIPTDIR, arch + endianness, iid, qemuInitValue
    )
    cmd += " 2>&1 > /dev/null"

    # 启动 QEMU
    qemu_proc = subprocess.Popen(cmd, shell=True)

    try:
 
        time.sleep(80)

    
        try:
            socat_ok, logs_mode = socat_and_save(iid)
            print(f"socat_ok={socat_ok}, logs_mode={logs_mode}")
        except Exception as e:
            print(f"[!] socat_and_save failed: {e}")
            socat_ok, logs_mode = False, "none"

      
        qemu_proc.wait(timeout=TIMEOUT + 10)
    except subprocess.TimeoutExpired:
        print("[!] QEMU did not exit in time, sending SIGINT...")
        qemu_proc.send_signal(signal.SIGINT)
        try:
            qemu_proc.wait(10)
        except subprocess.TimeoutExpired:
            print("[!] Forcing QEMU to exit with SIGKILL")
            qemu_proc.kill()

   
    loopFile = mountImage(targetDir)

    firmware_dir = os.path.join(targetDir, 'image', 'firmadyne')
    if os.path.isdir(firmware_dir):

        if (logs_mode == "firmadyne") or (logs_mode == "auto"):
            for fname in ('ps.log', 'ip.log'):
                src = os.path.join(firmware_dir, fname)
                if os.path.exists(src):
                    dst = os.path.join(targetDir, fname)
                    print(f"[*] Copying {src} -> {dst}")
                    shutil.copy(src, dst)
                else:
                    print(f"[-] {src} not found in image, not copying.")
        else:
            print(f"[*] Skip copying /image/firmadyne/*.log because logs_mode={logs_mode}")

    else:
        print(f"[!] firmware_dir {firmware_dir} does not exist in image!")

    # umountImage(targetDir, loopFile)
    # loopFile = mountImage(targetDir)
    if not os.path.exists(targetDir + '/image/firmadyne/nvram_files'):
        print("Infer NVRAM default file!\n")
        os.system("{}/inferDefault.py {}".format(SCRIPTDIR, iid))
    umountImage(targetDir, loopFile)

    data = open("%s/qemu.initial.serial.log" % targetDir, 'rb').read()
    ports = findPorts(data, endianness)

    ip_path = os.path.join(targetDir, "ip.log")
    ip_data = open(ip_path, "rb").read() if os.path.exists(ip_path) else None

    # mode:
    #   "serial" = serial log only
    #   "ip_addr" = ip addr only
    #   "union" = union(serial log, ip addr)
    if socat_ok and _has_valid_ip(ip_data):
        iface_parse_mode = "ip_addr"
    else:
        iface_parse_mode = "serial"
    # iface_parse_mode="union"
    # iface_parse_mode = "serial"
    print("iface_parse_mode: %s (socat_ok=%s)" % (iface_parse_mode, socat_ok))

    # find interfaces with non loopback ip addresses
    # ("eth0", "192.168.0.1"),
    ifacesWithIps = findNonLoInterfaces(data, endianness, mode=iface_parse_mode, ip_data=ip_data)
    # find changes of mac addresses for devices
    # ("vlan1@eth2","00:11:22:33:44:58"),
    macChanges = findMacChanges(data, endianness, mode=iface_parse_mode, ip_data=ip_data)
    print('[*] Interfaces: %r' % ifacesWithIps)

    if iface_parse_mode == "ip_addr":
        networkList, cfg_cmds = getNetworkList(data, ifacesWithIps, macChanges,
                                               mode=iface_parse_mode, ip_data=ip_data)
        if cfg_cmds:
            netfix_file = os.path.join(targetDir, "second_stage_netfix.list")
            with open(netfix_file, "w") as f:
                for cmd in cfg_cmds:
                    cmd = cmd.strip()
                    if cmd:
                        f.write(cmd + "\n")
    else:
        networkList = getNetworkList(data, ifacesWithIps, macChanges,
                                     mode=iface_parse_mode, ip_data=ip_data)
        cfg_cmds = []
    return qemuInitValue, networkList, targetFile, targetData, ports, cfg_cmds, socat_ok, iface_parse_mode


def socat_and_save(IID, mode="auto"):
    global SCRATCHDIR

    def _safe_write(path, text):
        
        if not text:
            return False
        if not text.strip():
            return False
        # 真写
        with open(path, "w") as f:
            f.write(text)
        return True

    def _ensure_proc_mounted(sc):
        
        print("[*] Attempting to mount /proc...")

        mount_cmd = b"/firmadyne/busybox mount -t proc proc /proc 2>&1; echo [[MOUNT-PROC-END]]\n"
        sc.send(mount_cmd)

        try:
            out = sc.recvuntil(b"[[MOUNT-PROC-END]]", timeout=5)
            print("[*] Mount /proc output:\n", out.decode(errors="ignore"))
        except Exception as e:
            print(f"[!] _ensure_proc_mounted: recv mount proc failed: {e}")
            return False

        time.sleep(3)
        
        check_cmd = b"/firmadyne/busybox sh -c 'mount | /firmadyne/busybox grep \" on /proc \"' ; echo [[PROC-END]]\n"
        sc.send(check_cmd)
        try:
            out2 = sc.recvuntil(b"[[PROC-END]]", timeout=5)
            text = out2.decode(errors="ignore")
            if " on /proc " in text:
                print("[*] /proc mounted successfully.")
                return True
            else:
                print("[!] /proc mount check failed.")
                return False
        except Exception as e:
            print(f"[!] _ensure_proc_mounted: recv mount check failed: {e}")
            return False

    def _parse_ls_sizes(t):
        sizes = {}
        for line in t.splitlines():
            line = line.strip()
            if "/firmadyne/ip.log" in line or "/firmadyne/ps.log" in line:
                parts = line.split()
                if len(parts) >= 9 and parts[0].startswith("-"):
                    try:
                        size = int(parts[4])
                        path = parts[-1]
                        sizes[path] = size
                    except:
                        pass
        return sizes


    def _try_guest_loop(sc):
       
        proc_ok = _ensure_proc_mounted(sc)
        if not proc_ok:
            print("[!] _try_guest_loop: /proc not mounted or mount failed; ps 很可能为空。")

        loop_cmd = (
            b"/firmadyne/busybox sh -c '"
            b"while /firmadyne/busybox true; do "
            b"/firmadyne/busybox ps > /firmadyne/ps.log; "
            b"/firmadyne/busybox ip addr > /firmadyne/ip.log; "
            b"/firmadyne/busybox sync; "
            b"/firmadyne/busybox sleep 10; "
            b"done &' \n"
        )
        sc.send(loop_cmd)
        time.sleep(1)

        time.sleep(30)

        check_cmd = (
            b"/firmadyne/busybox sh -c '"
            b"ls -l /firmadyne/ps.log /firmadyne/ip.log 2>&1; "
            b"' ; echo '[[FIRMWELD-LOG-END]]'\n"
        )
        sc.send(check_cmd)

        try:
            out = sc.recvuntil(b"[[FIRMWELD-LOG-END]]", timeout=10)
            text = out.decode(errors="ignore")
            print("[*] Guest log check output:\n", text)

            if "No such file" in text:
                return False

            sizes = _parse_ls_sizes(text)
            ps_sz = sizes.get("/firmadyne/ps.log", 0)
            ip_sz = sizes.get("/firmadyne/ip.log", 0)

            if ps_sz > 0 or ip_sz > 0:
                return True

            print("[!] ps.log / ip.log exist but are zero size — treat guest-loop as failed")

            return False

        except Exception as e:
            print(f"[!] recv log check failed: {e}")
            return False

    def _try_host_snapshots(sc, iid):
        proc_ok = _ensure_proc_mounted(sc)
        if not proc_ok:
            print("[!] _try_host_snapshots: /proc 未挂载或挂载失败，ps 输出极可能为空。")

        duration = 80
        interval = 10
        end_time = time.time() + duration

        scratch_iid_dir = os.path.join(SCRATCHDIR, str(iid))
        os.makedirs(scratch_iid_dir, exist_ok=True)
        ps_path = os.path.join(scratch_iid_dir, "ps.log")
        ip_path = os.path.join(scratch_iid_dir, "ip.log")

        any_written = False

        def _flush(sc, t=0.2):
            try:
                sc.recv(timeout=t)
            except Exception:
                pass

        def _capture_between(sc, cmd_bytes, timeout=12):
           
            token = f"{int(time.time() * 1000)}-{os.getpid()}"
            BEGIN = f"[[BEGIN-{token}]]".encode()
            END = f"[[END-{token}]]".encode()

           
            try:
                sc.recv(timeout=0.2)
            except Exception:
                pass

            wrapped = (
                    b"/firmadyne/busybox sh -c '"
                    b"/firmadyne/busybox echo " + BEGIN + b"; "
                    + cmd_bytes + b" 2>&1; "
                    b"/firmadyne/busybox echo " + END +
                    b"'"
            )
            sc.send(wrapped + b"\n")

            raw = sc.recvuntil(END, timeout=timeout)

            i = raw.find(BEGIN)
            j = raw.rfind(END)
            if i == -1 or j == -1 or j < i:
                return b""

            mid = raw[i + len(BEGIN): j]

            text = mid.decode(errors="ignore")
            cleaned_lines = []
            for line in text.splitlines():
                s = line.strip()
                if not s:
                    continue

                if "/firmadyne/busybox sh -c" in s:
                    continue
                if "echo [[BEGIN-" in s or "echo [[END-" in s:
                    continue

                if s.startswith("; /firmadyne") or s.startswith("/busybox"):
                    continue

                cleaned_lines.append(line)

            out = "\n".join(cleaned_lines).strip()
            return (out + "\n").encode() if out else b""

        def _looks_like_ps(txt):
            t = (txt or "")
            return ("PID" in t and "COMMAND" in t) or ("kthreadd" in t)

        def _has_ipv4(txt):
            if not txt:
                return False
            for m in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', txt):
                if m != "0.0.0.0":
                    parts = m.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        return True
            return False

        while time.time() < end_time:
            # ---- 1) ps ----
            try:
                raw_ps = _capture_between(sc, b"/firmadyne/busybox ps", timeout=12)
            except Exception as e:
                print(f"[!] capture ps failed: {e}")
                break

            ps_text = raw_ps.decode(errors="ignore")
            wrote_ps = _safe_write(ps_path, ps_text)
            any_written = any_written or wrote_ps

            # ---- 2) ip ----
            ip_text = ""
            try:
                raw_ip = _capture_between(sc, b"/firmadyne/busybox ip addr", timeout=12)
                ip_text = raw_ip.decode(errors="ignore").strip()
            except Exception:
                ip_text = ""

            wrote_ip = _safe_write(ip_path, ip_text)
            any_written = any_written or wrote_ip
            print("[*] ps/ip snapshot updated.")

            sleep_left = min(interval, end_time - time.time())
            if sleep_left > 0:
                time.sleep(sleep_left)

        def _non_empty(path):
            return os.path.exists(path) and os.path.getsize(path) > 0

        if any_written and (_non_empty(ps_path) or _non_empty(ip_path)):
            return True
        return False

    time.sleep(1)
    subprocess.run(
        ["sudo", "chmod", "-R", "a+rwx", f"/tmp/qemu.{IID}.S1"],
        check=False
    )
    time.sleep(1)

    sc = None
    try:
        sc = pwn.process(["socat", "-", f"UNIX-CLIENT:/tmp/qemu.{IID}.S1"])
        time.sleep(1)

        sc.send(b"\n")
        time.sleep(1)

        # shell '#'
        try:
            r = sc.recvuntil(b"#", timeout=60)
            print(r.decode(errors="ignore"))
        except Exception as e:
            print(f"[!] recvuntil(#) failed: {e}")
            return (False, "none")

        print("    - Socat ready, shell prompt and ls test OK, start log collection ...")
        # ---------- Step 1 ----------
        success = False
        logs_mode = "none"

        if mode in ("auto", "firmadyne"):
            loop_ok = _try_guest_loop(sc)
            if loop_ok:
                print("[*] Guest loop for /firmadyne/ps.log/ip.log started successfully.")
                success = True
                logs_mode = "firmadyne"

                return (success, logs_mode)

        # ---------- Step 2 ----------
        if not success and mode in ("auto", "scratch"):
            print("[*] Guest loop not available, fallback to host-side snapshots...")
            snap_ok = _try_host_snapshots(sc, IID)
            if snap_ok:
                print("[*] Host-side ps/ip snapshots collected.")
                success = True
                logs_mode = "scratch"
            else:
                print("[!] Host-side snapshots failed or logs empty.")
                return (None, "auto")

        return (success, logs_mode)

    finally:
        if sc is not None:
            try:
                sc.close()
            except Exception:
                pass

def findVlan2EthFromLog(iid, vlan_names=None):
    global SCRATCHDIR
    targetDir = SCRATCHDIR + '/' + str(iid)
    log_path = "%s/qemu.initial.serial.log" % targetDir

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    vlan_to_eth = {}

    vlan_promisc_re = re.compile(r'device\s+(vlan\d+)\s+entered promiscuous mode')
    eth_promisc_re = re.compile(r'device\s+(eth\d+)\s+entered promiscuous mode')

    for i, line in enumerate(lines):
        m_vlan = vlan_promisc_re.search(line)
        if not m_vlan:
            continue

        vlan_if = m_vlan.group(1)

        if vlan_names is not None and vlan_if not in vlan_names:
            continue

        if vlan_if in vlan_to_eth:
            continue

        for j in range(i + 1, min(i + 8, len(lines))):
            m_eth = eth_promisc_re.search(lines[j])
            if m_eth:
                eth_if = m_eth.group(1)
                vlan_to_eth[vlan_if] = eth_if
                break
    return vlan_to_eth


def checkNetwork(iid, networkList):
    filterNetworkList = []
    devList = ["eth0", "eth1", "eth2", "eth3"]
    result = "None"

    if checkVariable("FIRMWELD_NET"):
        devs = [dev for (ip, dev, vlan, mac, brif) in networkList]
        devs = set(devs)
        ips = [ip for (ip, dev, vlan, mac, brif) in networkList]
        ips = set(ips)
        # check "ethX" and bridge interfaces
        # bridge interface can be named guest-lan1, br0
        # wnr2000v4-V1.0.0.70.zip - mipseb
        # [('192.168.1.1', 'br0', None, None, 'br0'), ('10.0.2.15', 'eth0', None, None, 'br1')]
        # R6900
        # [('192.168.1.1', 'br0', None, None, 'br0'), ('20.45.150.190', 'eth0', None, None, 'eth0')]
        if (len(devs) > 1 and
                any([dev.startswith('eth') for dev in devs]) and
                any([not dev.startswith('eth') for dev in devs])):
            print("[*] Check router")
            # remove dhcp ip address
            networkList = [network for network in networkList if not network[1].startswith("eth")]
        # linksys FW_LAPAC1200_LAPAC1750_1.1.03.000
        # [('192.168.1.252', 'eth0', None, None, 'br0'), ('10.0.2.15', 'eth0', None, None, 'br0')]
        elif (len(ips) > 1 and
              any([ip.startswith("10.0.2.") for ip in ips]) and
              any([not ip.startswith("10.0.2.") for ip in ips])):
            print("[*] Check router")
            # remove dhcp ip address
            networkList = [network for network in networkList if not network[0].startswith("10.0.2.")]

        # br and eth
        if networkList:
            vlanNetworkList = [network for network in networkList if
                               not network[0].endswith(".0.0.0") and network[1].startswith("eth") and network[
                                   2] != None]
            ethNetworkList = [network for network in networkList if
                              not network[0].endswith(".0.0.0") and network[1].startswith("eth")]
            invalidEthNetworkList = [network for network in networkList if
                                     network[0].endswith(".0.0.0") and network[1].startswith("eth")]
            brNetworkList = [network for network in networkList if
                             not network[0].endswith(".0.0.0") and not network[1].startswith("eth")]
            invalidBrNetworkList = [network for network in networkList if
                                    network[0].endswith(".0.0.0") and not network[1].startswith("eth")]
            if vlanNetworkList:
                print("has vlan ethernet")
                filterNetworkList = vlanNetworkList
                result = "normal"
            elif ethNetworkList:
                print("has ethernet")
                filterNetworkList = ethNetworkList
                result = "normal"
            elif invalidEthNetworkList:
                print("has ethernet and invalid IP")
                for (ip, dev, vlan, mac, brif) in invalidEthNetworkList:
                    filterNetworkList.append(('192.168.0.1', dev, vlan, mac, brif))
                result = "reload"
            elif brNetworkList:
                print("only has bridge interface")
                mapped = False
                vlan_names = {dev for (_, dev, _, _, _) in brNetworkList
                              if isinstance(dev, str) and dev.startswith("vlan")}
                if vlan_names:
                    vlan_to_eth = findVlan2EthFromLog(iid, vlan_names)
                    if vlan_to_eth:
                        
                        for (ip, dev, vlan, mac, brif) in brNetworkList:
                            if dev in vlan_to_eth:
                                real_eth = vlan_to_eth[dev]
                                filterNetworkList.append((ip, real_eth, vlan, mac, brif))
                                mapped = True

                if not mapped:
                    for (ip, dev, vlan, mac, brif) in brNetworkList:
                        if devList:
                            new_dev = devList.pop(0)
                            filterNetworkList.append((ip, new_dev, vlan, mac, brif))

                result = "bridge"
                # for (ip, dev, vlan, mac, brif) in brNetworkList:
                #     if devList:
                #         dev = devList.pop(0)
                #         filterNetworkList.append((ip, dev, vlan, mac, brif))
                # result = "bridge"
            elif invalidBrNetworkList:
                print("only has bridge interface and invalid IP")
                for (ip, dev, vlan, mac, brif) in invalidBrNetworkList:
                    if devList:
                        dev = devList.pop(0)
                        filterNetworkList.append(('192.168.0.1', dev, vlan, mac, brif))
                result = "bridgereload"

        else:
            print("[-] no network interface: bring up default network")
            filterNetworkList.append(('192.168.0.1', 'eth0', None, None, "br0"))
            result = "default"
    else:  # if checkVariable("FIRMWELD_NET"):
        filterNetworkList = networkList

    return filterNetworkList, result  # (network_type)


def process(iid, arch, endianness, makeQemuCmd=False, outfile=None, brand="Unknown"):

    global SCRATCHDIR, SCRIPTDIR

    success = False # True

    try_inits=True

    if try_inits:
        init_list = open(f"{SCRATCHDIR}/{iid}/init").read().split('\n')[:-1]
    else:
        init_list = ["/firmadyne/preInit.sh"]

    
    for init in init_list:
        with open(SCRATCHDIR + "/" + str(iid) + "/current_init", 'w') as out:
            out.write(init)
        # init = "/sbin/preinit"
        # /firmadyne/preInit.sh
        print("[*] First-stage emulation with /firmadyne/preInit.sh ...")
        qemuInitValue, networkList, targetFile, targetData, ports, cfg_cmds, socat_ok, iface_parse_mode = inferNetwork(
            iid, arch, endianness, init)

        print("[*] ports: %r" % ports)
        print(f"[*] networkInfo: {networkList!r}")
        print(f"[*] cfg_cmds: {cfg_cmds!r}")

        if iface_parse_mode == "ip_addr":
            network_type = "None"
        else:
            networkList, network_type = checkNetwork(iid, networkList)
            print("[*] filter network info: %r" % networkList)

        if networkList:
            print("[*] Using ip.log-based network inference (first init) ...")
            success = run_second_stage_with_network(
                iid,
                arch,
                endianness,
                networkList,
                outfile,
                qemuInitValue,
                ports,
                brand=brand,
                network_type=network_type,
            )
            if success:
                return True
                break

        if targetData != '':
            targetDir = SCRATCHDIR + '/' + str(iid)
            loopFile = mountImage(targetDir)
            with open(targetFile, 'w') as out:
                out.write(targetData)
            umountImage(targetDir, loopFile)

    return success

def run_second_stage_with_network(iid, arch, endianness,
                                  networkList, outfile,
                                  qemuInitValue, ports, brand,
                                  network_type):
    global SCRATCHDIR, SCRIPTDIR

    targetDir = os.path.join(SCRATCHDIR, str(iid))

    service_cmd = ""
    ps_log_path = os.path.join(targetDir, "ps.log")
    service_path = os.path.join(targetDir, "service")

    if os.path.exists(service_path):
        svc_line = open(service_path).read().strip()
        svc_word = os.path.basename(svc_line.split()[0])
        if not os.path.exists(ps_log_path):

            service_cmd = svc_line
            print(f"[+] ps.log missing, will start service {svc_word} in run.sh")
        else:

            ps_content = open(ps_log_path).read()
            if svc_word not in ps_content:
                service_cmd = svc_line
                print(f"[+] Detected missing service {svc_word}, will restart in run.sh")

    # ip_num / ip.N / isDhcp
    ips = [ip for (ip, dev, vlan, mac, brif) in networkList]
    ips = list(set(ips))  
    with open(os.path.join(targetDir, "ip_num"), "w") as out:
        out.write(str(len(ips)))

    for idx, ip in enumerate(ips):
        with open(os.path.join(targetDir, f"ip.{idx}"), "w") as out:
            out.write(str(ip))

    isUserNetwork = any(isDhcpIp(ip) for ip in ips)
    with open(os.path.join(targetDir, "isDhcp"), "w") as out:
        out.write("true" if isUserNetwork else "false")

    qemuCommandLine = qemuCmd(
        iid,
        networkList,
        ports=ports,
        network_type=network_type,
        arch=arch,
        endianness=endianness,
        qemuInitValue=qemuInitValue,
        isUserNetwork=isUserNetwork,
        service_cmd=service_cmd,
    )

    with open(outfile, "w") as out:
        out.write(qemuCommandLine)
    os.chmod(outfile, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IROTH | stat.S_IXOTH)

    os.system("./scripts/check_emulation.sh {} {}".format(iid, arch + endianness, brand))

    web_flag = os.path.join(targetDir, "web")
    ping_flag = os.path.join(targetDir, "ping")

    web_ok = os.path.exists(web_flag) and open(web_flag).read().strip() == "true"
    ping_ok = os.path.exists(ping_flag) and open(ping_flag).read().strip() == "true"

    if web_ok and ping_ok:
        print("[*] Second-stage emulation (ip.log-based) succeeded (ping & web).")
        return True

    print("[*] Second-stage emulation (ip.log-based) did NOT succeed, will fallback.")
    return False

def archEnd(value):
    arch = None
    end = None

    tmp = value.lower()
    if tmp.startswith("mips"):
        arch = "mips"
    elif tmp.startswith("arm"):
        arch = "arm"
    if tmp.endswith("el"):
        end = "el"
    elif tmp.endswith("eb"):
        end = "eb"
    return (arch, end)


def getWorkDir():
    if os.path.isfile("./firmweld.config"):
        return os.getcwd()
    elif os.path.isfile("../firmweld.config"):
        path = os.getcwd()
        return path[:path.rfind('/')]
    else:
        return None


def main():
    makeQemuCmd = False
    iid = None
    outfile = None
    arch = None
    endianness = None
    brand = "Unknown"
    workDir = getWorkDir()
    if not workDir:
        raise Exception("Can't find firmweld.config file")

    global SCRATCHDIR
    global SCRIPTDIR
    SCRATCHDIR = workDir + '/scratch'
    SCRIPTDIR = workDir + '/scripts'

    (opts, argv) = getopt.getopt(sys.argv[1:], 'i:a:oqdb:')
    for (k, v) in opts:
        if k == '-d':
            global debug
            debug += 1
        if k == '-q':
            makeQemuCmd = True
        if k == '-i':
            iid = int(v)
        if k == '-o':
            outfile = True
        if k == '-a':
            (arch, endianness) = archEnd(v)
        if k == '-b':
            brand = str(v)

    if not arch or not endianness:
        raise Exception("Either arch or endianness not found try mipsel/mipseb/armel/armeb")

    if outfile and iid:
        outfile = """%s/%i/run.sh""" % (SCRATCHDIR, iid)
    if debug:
        print("processing %i" % iid)

    process(iid, arch, endianness, makeQemuCmd, outfile, brand)


if __name__ == "__main__":
    main()