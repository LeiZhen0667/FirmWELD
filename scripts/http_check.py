#!/usr/bin/env python3
import os, sys
from telnetlib import IP
import requests
from hashlib import md5
import base64
import time
import math
import selenium
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException
from requests.auth import HTTPDigestAuth
import subprocess
import lxml.html

from Initializer import *

USER_AUTHS = ['admin', '']
PASSWORD_AUTHS = ['', 'admin', 'password', '1234']
MAX_RETRIES = 3


class URLCheck:

    def __init__(self, ip, port, brand, analysis_path):
        self.ip = ip
        self.port = port
        self.url = "http://%s:%s" % (ip, port)
        self.brand = brand
        self.analysis_path = analysis_path

        # session
        self.user = ""
        self.password = ""
        self.headers = None
        self.data = ""
        self.working_curl = ""
        self.reply = None
        self.session = None
        self.last_status_code = -1
        self.login_type = ""
        self.loginurl = ""

        # flags
        self.curl_success = False
        self.login_success = False
        self.login_needed = False
        self.initializer_done = False
        self.wellformed = False
        self.timedout = False

    def _read_ip_from_workdir(self) -> str:

        ip_file = os.path.join(self.analysis_path, "ip")
        try:
            with open(ip_file, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        return ip
        except Exception as e:
            print(f"    - failed to read ip file: {ip_file}, err={e}")
        return ""

    def _wget_fetch(self, timeout: int = 5, path: str = "") -> bytes:

        ip = (self.ip or "").strip()
        if not ip:
            ip = self._read_ip_from_workdir()
        if not ip:
            return b""

        port = str(self.port).strip()

        suffix = ""
        if path:
            suffix = path if path.startswith("/") else ("/" + path)

        def run_wget(url: str) -> bytes:
            cmd = [
                "wget",
                "-qO-",
                f"--timeout={timeout}",
                "--tries=1",
            ]
            if url.startswith("https://"):
                cmd.append("--no-check-certificate")
            cmd.append(url)

            try:
                p = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if p.returncode == 0 and p.stdout:
                    return p.stdout
                return b""
            except Exception:
                return b""

        http_url = f"http://{ip}:{port}{suffix}"
        page = run_wget(http_url)
        if page:
            return page

        https_url = f"https://{ip}:{port}{suffix}"
        page = run_wget(https_url)
        return page or b""

    def logincheck(self, session):

        login_type = Login.check_login_type(self.url, self.brand)
        if login_type == "connection error":
            return False, False
        if login_type == "unknown":
            return True, False

        self.login_type = login_type

        print("    - Login Type: ", self.login_type)
        logged_in = False
        headers = {}
        reply = None
        for user in USER_AUTHS:
            for password in PASSWORD_AUTHS:
                if self.login_success:
                    user = self.user
                    password = self.password
                try:
                    print("      - Trying user: %s password: %s" % (user, password))
                    logged_in, headers, payload, loginurl = Login.login(
                        session, self.brand, self.url, self.login_type, user, password
                    )
                    print("      - logged in", logged_in)
                except Exception as e:
                    print("      - ERROR login attempt failed")
                    print(e)
                time.sleep(2)
                if logged_in:
                    # retry: make sure the login actually works
                    try:
                        logged_in, _, _, _ = Login.login(
                            session, self.brand, self.url, self.login_type, user, password
                        )
                    except Exception as e:
                        print("      - ERROR login attempt failed")
                        print(e)
                        logged_in = False
                    if not logged_in:
                        print("      x- false login success, retry")
                        continue
                    self.user = user
                    self.password = password
                    self.headers = headers
                    self.loginurl = loginurl
                    if payload is not None:
                        self.data = str(payload)
                    else:
                        self.data = ""
                    break
            if logged_in:
                break

        return logged_in, True

    def webcheck(self):

        wbc = WebCheck()
        retryurl = ""
        wbc.Initialize(self.analysis_path)

        # 默认不带 auth
        auth = ""

        wellformed = False

        # 1) Selenium WebCheck
        try:
            wbc.Connect(self.url, auth)
            wellformed, self.last_status_code = wbc.Check()

            if wellformed and self.last_status_code == 200:
                print("=" * 50)
                print("    - second check")
                print("=" * 50)
                wellformed, self.last_status_code = wbc.Check()

            if self.last_status_code == 401:
                print("    - got 401, trying logincheck once...")
                try:
                    sess = requests.Session()
                    logged_in, login_needed = self.logincheck(sess)
                    sess.close()
                except Exception as e:
                    print("    - logincheck exception:", e)
                    logged_in, login_needed = (False, True)

                if login_needed and logged_in:
                    auth = "%s:%s" % (self.user, self.password)
                    # 若 loginurl 有返回，优先用 loginurl
                    if self.loginurl:
                        self.url = self.loginurl
                    print("    - retry WebCheck with auth", auth)

                    try:
                        wbc.Close()
                    except Exception:
                        pass
                    wbc = WebCheck()
                    wbc.Initialize(self.analysis_path)

                    wbc.Connect(self.url, auth)
                    wellformed, self.last_status_code = wbc.Check()
                    if wellformed and self.last_status_code == 200:
                        print("=" * 50)
                        print("    - second check (authed)")
                        print("=" * 50)
                        wellformed, self.last_status_code = wbc.Check()

            if self.last_status_code == 401:
                retryurl = getattr(wbc, "current_url", "") or ""

        except Exception as e:
            print("    - WebCheck exception:", e)
            wellformed = False
        finally:
            try:
                wbc.Close()
            except Exception:
                pass

        if not wellformed:
            print("    - trying with wget fetch...")
            page_source = self._wget_fetch(timeout=5, path="")

            if not page_source:
                page_source = self._wget_fetch(timeout=5, path="index.htm")

            if page_source:
                print("    - wget fetched content (first 512 bytes):")
                try:
                    preview = page_source[:512].decode("utf-8", errors="replace")
                except Exception:
                    preview = str(page_source[:512])
                print("--------------------------------------------------")
                print(preview)
                print("--------------------------------------------------")

                src_l = page_source.lower()
                looks_like_html = (b"<html" in src_l) or (b"<script" in src_l)

                non_empty_text = False
                if looks_like_html:
                    try:
                        doc = lxml.html.fromstring(page_source)

                        raw_text = doc.text_content()
                        has_text = bool(raw_text and raw_text.strip())

                        semantic_elems = doc.xpath("//meta | //script | //link | //style")
                        has_semantic_elem = len(semantic_elems) > 0

                        has_attrs = False
                        for tag in ["html", "head", "body"]:
                            elems = doc.xpath(f"//{tag}")
                            if elems and elems[0].attrib:
                                has_attrs = True
                                break

                        is_pure_skeleton = (not has_text and
                                            not has_semantic_elem and
                                            not has_attrs)
                        non_empty_text = not is_pure_skeleton

                    except Exception as e:
                        print("    - wget html parse error:", e)
                        non_empty_text = False

                if looks_like_html and non_empty_text:
                    print("    - wget content looks like valid non-empty HTML/JS page, treating as wellformed=True")
                    wellformed = True
                    self.last_status_code = 200
                else:
                    print("    - wget fallback did not meet conditions: "
                          f"looks_like_html={looks_like_html}, non_empty_text={non_empty_text}")

        return wellformed, retryurl

    def probe(self):

        self.wellformed = False
        self.last_status_code = -1

        print("[+] webcheck-only")
        print("[+] Probing %s..." % self.url)

        wellformed, retryurl = self.webcheck()

        if len(retryurl) > 0 and self.url != retryurl:
            print("    - retrying with new url", retryurl)
            self.url = retryurl
            wellformed, _ = self.webcheck()

        self.wellformed = bool(wellformed)

        if not self.wellformed:
            print("    - WebCheck failed!")
            if self.last_status_code == 200:
                self.last_status_code = 204

        return self.last_status_code != -1


class HTTPInteractionCheck:

    def __init__(self, brand, analysis_path, full_timeout=False):
        self.brand = brand
        self.analysis_path = analysis_path
        self.urlchecks = []
        self.full_timeout = full_timeout

    def probe(self, ips, ports):
        self.urlchecks.clear()
        for ip in ips:
            for port in ports:
                uc = URLCheck(ip, port, self.brand, self.analysis_path)
                ok = uc.probe()
                if ok:
                    self.urlchecks.append(uc)

        if not self.full_timeout:
            if len(self.urlchecks) > 0:
                return True
        return False

    def get_port(self, uc):
        return int(uc.port)

    def get_url(self, uc):
        return uc.url

    def check(self, trace, exit_code, timedout, errored, strict):
        connected = False
        if not errored:
            if self.urlchecks:
                self.urlchecks.sort(key=self.get_url)
                self.urlchecks.sort(key=self.get_port)
                for uc in self.urlchecks:
                    print("    >>> checking", uc.url, uc.last_status_code)
                    if uc.last_status_code == 200:
                        print("Status Code:", uc.last_status_code)
                        if strict:
                            if uc.wellformed:
                                return True, uc.wellformed, True
                        else:
                            return True, uc.wellformed, True
                    else:
                        connected = connected or False

                    if uc.last_status_code != -1:
                        print("Status Code:", uc.last_status_code)

        return False, False, connected


if __name__ == "__main__":
    start_time = time.time()

    if len(sys.argv) < 3:
        print("USAGE: http_check.py [BRAND] [ANALYSIS_PATH] [URL;URL;URL (optional)]")
        sys.exit(1)

    brand = sys.argv[1]
    analysis_path = sys.argv[2]

    if len(sys.argv) >= 4:
        ips_arg = sys.argv[3]
        potential_urls = [ip for ip in ips_arg.split(";") if ip.strip()]
    else:
        ip_file = os.path.join(analysis_path, "ip")
        if not os.path.exists(ip_file):
            print("Error: ip file not found at", ip_file)
            sys.exit(1)
        with open(ip_file, "r") as f:
            potential_urls = [line.strip() for line in f if line.strip()]

    ports = ["80", "443", "1900"]
    print("Running http_check (webcheck-only): ", brand, analysis_path, potential_urls, ports)
    checker = HTTPInteractionCheck(brand, analysis_path)

    probe_success = checker.probe(potential_urls, ports)

    deep_web_ok = False

    if probe_success:
        success, wellformed, _ = checker.check(
            trace=None,
            exit_code=None,
            timedout=False,
            errored=False,
            strict=True
        )

        if success and wellformed:
            deep_web_ok = True
            print("HTTP_DEEP_RESULT true")
            print("Success, filesystem runs!")
        else:
            deep_web_ok = False
            print("HTTP_DEEP_RESULT false")
            print("[!] No well-formed HTTP 200 web interface found.")
    else:
        deep_web_ok = False
        print("HTTP_DEEP_RESULT false")
        print("[!] No HTTP candidate survived deep checking.")

    if deep_web_ok:
        end_time = time.time()
        elapsed = end_time - start_time

        web_acc_file = os.path.join(analysis_path, "web_acc")
        time_web_acc_file = os.path.join(analysis_path, "time_web_acc")

        with open(web_acc_file, "w") as f:
            f.write("true\n")

        with open(time_web_acc_file, "w") as f:
            f.write(str(elapsed) + "\n")

        sys.exit(0)
    else:
        sys.exit(1)
