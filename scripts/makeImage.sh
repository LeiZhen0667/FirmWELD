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
    echo "Usage: makeImage.sh <image ID> [<architecture>]"
    exit 1
fi

if check_root; then
    echo "Error: This script requires root privileges!"
    exit 1
fi

IID=${1}
ARCH=${2}
BRAND=${3:-""}
FILENAME=${4:-""}

echo "----Running----"
WORK_DIR=`get_scratch ${IID}`
IMAGE=`get_fs ${IID}`
IMAGE_DIR=`get_fs_mount ${IID}`

echo "----Copying Filesystem Tarball----"
mkdir -p "${WORK_DIR}"
chmod a+rwx "${WORK_DIR}"
chown -R "${USER}" "${WORK_DIR}"
chgrp -R "${USER}" "${WORK_DIR}"

if [ ! -e "${WORK_DIR}/${IID}.tar.gz" ]; then
    if [ ! -e "${TARBALL_DIR}/${IID}.tar.gz" ]; then
        echo "Error: Cannot find tarball of root filesystem for ${IID}!"
        exit 1
    else
        cp "${TARBALL_DIR}/${IID}.tar.gz" "${WORK_DIR}/${IID}.tar.gz"
    fi
fi

echo "----Creating QEMU Image----"
qemu-img create -f raw "${IMAGE}" 1G
chmod a+rw "${IMAGE}"

echo "----Creating Partition Table----"
echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${IMAGE}"

echo "----Mounting QEMU Image----"
DEVICE=`add_partition ${IMAGE}`

echo "----Creating Filesystem----"
sync
mkfs.ext2 "${DEVICE}"

echo "----Making QEMU Image Mountpoint----"
if [ ! -e "${IMAGE_DIR}" ]; then
    mkdir "${IMAGE_DIR}"
    chown "${USER}" "${IMAGE_DIR}"
fi

echo "----Mounting QEMU Image Partition----"
sync
mount "${DEVICE}" "${IMAGE_DIR}"

echo "----Extracting Filesystem Tarball----"
tar -xf "${WORK_DIR}/$IID.tar.gz" -C "${IMAGE_DIR}"
rm "${WORK_DIR}/${IID}.tar.gz"

if [ "${BRAND}" = "asus" ] && [ -d "${IMAGE_DIR}/www" ]; then
  ( cd "${IMAGE_DIR}" || exit 1
    for entry in www/*; do
      [ -e "$entry" ] || continue
      base="$(basename "$entry")"
      [ -e "$base" ] && continue
      ln -s "www/$base" "$base"
    done
  )
fi

echo "----Creating FIRMADYNE Directories----"
mkdir "${IMAGE_DIR}/firmadyne/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram/"
mkdir "${IMAGE_DIR}/firmadyne/libnvram.override/"

cp $(which busybox) "${IMAGE_DIR}"
cp $(which bash-static) "${IMAGE_DIR}"
echo "----Finding Init (chroot)----"
if [ -e "${WORK_DIR}/kernelInit" ]; then
  cp "${WORK_DIR}/kernelInit" "${IMAGE_DIR}"
fi
cp "${SCRIPT_DIR}/inferFile.sh" "${IMAGE_DIR}"
FIRMWELD_BOOT=${FIRMWELD_BOOT} FIRMWELD_ETC=${FIRMWELD_ETC} chroot "${IMAGE_DIR}" /bash-static /inferFile.sh
rm "${IMAGE_DIR}/bash-static"
rm "${IMAGE_DIR}/inferFile.sh"
if [ -e "${IMAGE_DIR}/kernelInit" ]; then
  rm "${IMAGE_DIR}/kernelInit"
fi

mv ${IMAGE_DIR}/firmadyne/init ${WORK_DIR}
if [ -e ${IMAGE_DIR}/firmadyne/service ]; then
  cp ${IMAGE_DIR}/firmadyne/service ${WORK_DIR}
fi

echo "----Patching Filesystem (chroot)----"
cp "${SCRIPT_DIR}/fixImage.sh" "${IMAGE_DIR}"
FIRMWELD_BOOT=${FIRMWELD_BOOT} FIRMWELD_ETC=${FIRMWELD_ETC} chroot "${IMAGE_DIR}" /busybox ash /fixImage.sh
rm "${IMAGE_DIR}/fixImage.sh"
rm "${IMAGE_DIR}/busybox"

echo "----Setting up FIRMADYNE----"
COPIED_LIBM=false

for BINARY_NAME in "${BINARIES[@]}"
do
    BINARY_PATH=`get_binary ${BINARY_NAME} ${ARCH}`
    cp "${BINARY_PATH}" "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"
    chmod a+x "${IMAGE_DIR}/firmadyne/${BINARY_NAME}"

    # ---- Copy libm ONLY when BRAND is D-link and ARCH is mipseb ----
    if [ "${COPIED_LIBM}" = "false" ]; then
        if [ "${BRAND}" = "dlink" ] && [ "${ARCH}" = "mipseb" ]; then
            BIN_DIR="$(dirname "${BINARY_PATH}")"
            LIBM_SRC="${BIN_DIR}/libm-0.9.30.3.so.mipseb"
            LIBM_DST_DIR="${IMAGE_DIR}/lib"
            LIBM_DST="${LIBM_DST_DIR}/libm-0.9.30.so"

            mkdir -p "${LIBM_DST_DIR}"

            if [ -f "${LIBM_SRC}" ] && [ ! -f "${LIBM_DST}" ]; then
                cp "${LIBM_SRC}" "${LIBM_DST}"
                echo "[+] Copied ${LIBM_SRC} -> ${LIBM_DST} (brand=${BRAND}, arch=${ARCH})"
            fi

            COPIED_LIBM=true
        fi
    fi
done


mknod -m 666 "${IMAGE_DIR}/firmadyne/ttyS1" c 4 65

cp "${SCRIPT_DIR}/preInit.sh" "${IMAGE_DIR}/firmadyne/preInit.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/preInit.sh"

cp "${SCRIPT_DIR}/network.sh" "${IMAGE_DIR}/firmadyne/network.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/network.sh"

cp "${SCRIPT_DIR}/run_service.sh" "${IMAGE_DIR}/firmadyne/run_service.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/run_service.sh"

cp "${SCRIPT_DIR}/loop4ip_ps.sh" "${IMAGE_DIR}/firmadyne/loop4ip_ps.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/loop4ip_ps.sh"

cp "${SCRIPT_DIR}/injectionChecker.sh" "${IMAGE_DIR}/bin/a"
chmod a+x "${IMAGE_DIR}/bin/a"

touch "${IMAGE_DIR}/firmadyne/debug.sh"
chmod a+x "${IMAGE_DIR}/firmadyne/debug.sh"

if (! ${FIRMWELD_ETC}); then
  sed -i 's/sleep 60/sleep 15/g' "${IMAGE_DIR}/firmadyne/network.sh"
  sed -i 's/sleep 120/sleep 30/g' "${IMAGE_DIR}/firmadyne/run_service.sh"
  sed -i 's@/firmadyne/sh@/bin/sh@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
  sed -i 's@BUSYBOX=/firmadyne/busybox@BUSYBOX=@g' ${IMAGE_DIR}/firmadyne/{preInit.sh,network.sh,run_service.sh}
fi

echo "----Unmounting QEMU Image----"
sync
umount "${IMAGE_DIR}"
del_partition ${DEVICE:0:$((${#DEVICE}-2))}

DEVICE=`add_partition ${IMAGE}`
e2fsck -y ${DEVICE}
sync
sleep 1
del_partition ${DEVICE:0:$((${#DEVICE}-2))}
