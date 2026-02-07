# FirmWELD

FirmWELD consists of a fully automated firmware emulation framework focused on interactive web functionalities and a firmware identification scheme. We evaluated FirmWELD using 7,971 firmware images from wireless routers and IP cameras produced by eight major vendors.

## Detailed Description

The rapid deployment of Internet of Things (IoT) devices on the Internet has significantly expanded the attack surface. In particular, N-day vulnerabilities pose serious threats to devices running outdated firmware. Consequently, Online Device Firmware Version Identification (ODFVI) is critical for assessing device security.

However, existing ODFVI methods lack an understanding of the interaction mechanisms of embedded web components, which limits their accuracy and scalability. In this work, we present FirmWELD, which employs heuristic-based techniques to emulate interactive web services within firmware, enabling large-scale and high-fidelity acquisition of embedded web resources.

Subsequently, FirmWELD utilizes a feature fusion attention network to capture semantic cues and subtle differences in embedded web interfaces.

To address the high inter-version similarity caused by web page reuse, we propose a novel metric loss function, namely the Hard Mining Cosine Triplet-Center Loss, which improves intra-class compactness and inter-class separability.

In our evaluation, FirmWELD successfully emulated 3,665 (46%) of 7,971 firmware images, achieving 1.6× higher coverage than the state-of-the-art full-system emulator FirmAE. Leveraging this emulation capability, FirmWELD collected 130,445 validated web pages and outperformed state-of-the-art ODFVI approaches by over 25% on average in both precision and recall.

Furthermore, the system revealed that only 2.28% of devices in our dataset were running the latest firmware version. Our evaluation also indicates that 6,684 devices (approximately 61.26%) with outdated firmware remain vulnerable to known exploits.

# Firmware Emulation

## Installation

Note that we tested FirmWELD on Ubuntu 20.04.

1. Clone `FirmWELD`
```console
$ git clone --recursive https://github.com/LeiZhen0667/FirmWELD
```

2. Run `download.sh` script.
```console
$ ./download.sh
```

3. Run FirmWELD using the Docker image [`firmweld:latest`](https://hub.docker.com/r/firmweld/firmweld).

```console
$ docker pull firmweld/firmweld:latest
$ docker run -it --rm firmweld/firmweld:latest
```

## Usage

1. Execute `init.sh` script.
```console
$ ./init.sh
```

2. Prepare a firmware.
```console
$ wget https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/DIR-868L_fw_revB_2-05b02_eu_multi_20161117.zip
```

3. Check emulation
```console
$ sudo ./run.sh -c <brand> <firmware>
```

### Docker

First, prepare a docker image.
```console
$ ./docker-init.sh
```

#### Parallel mode

Then, run one of the below commands. ```-ec``` checks only the emulation, and ```-ea``` checks the emulation and analyzes vulnerabilities.
```console
$ ./docker-helper.py -ec <brand> <firmware>
$ ./docker-helper.py -ea <brand> <firmware>
```

## Evaluation

### Emulation result

Google spreadsheet -
[view](https://docs.google.com/spreadsheets/d/1dbKxr_WOZ7UmneOogug1Zykj1erpfk-GzRNni8DjroI/edit?usp=sharing)

### Dataset

Google drive -
[download](https://drive.google.com/file/d/1hdm75NVKBvs-eVH9rKb5xfgryNSnsg_8/view?usp=sharing)

# Online Device Firmware Version Identification

For detailed information, please refer to [`DeepFW`] 
(https://github.com/LeiZhen0667/DeepFW).
