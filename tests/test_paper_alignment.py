import json
import tempfile
import threading
import unittest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import sys

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "scripts"))

from collect_web_resources import collect, resource_paths
from dependency_planner import build_ipc_plan
from export_deepfw_dataset import export
from karonte_bdg import run_karonte_bdg
from network_planner import choose_network_plan
from nvram_planner import build_nvram_plan
from runtime_state import merge_runtime_filesystem, parse_exec_sequence, parse_ip_state, parse_nvram_keys
from web_visibility import apply_visibility_plan, build_visibility_plan

KARONTE_TOOL = REPOSITORY / "third_party" / "karonte_bdg" / "tool"
sys.path.insert(0, str(KARONTE_TOOL))
from bdg.safe_search import find_elf_files_containing


IP_SAMPLE = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    link/loopback 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
3: eth1: <BROADCAST,MULTICAST> mtu 1500 master br0 state DOWN
    link/ether 52:54:00:12:34:58 brd ff:ff:ff:ff:ff:ff
4: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    link/ether 00:11:22:33:44:58 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.1/24 brd 192.168.1.255 scope global br0
"""


class RuntimeStateTests(unittest.TestCase):
    def test_parses_network_nvram_and_exec_evidence(self):
        network = parse_ip_state(IP_SAMPLE)
        by_name = {item["name"]: item for item in network["interfaces"]}
        self.assertEqual(by_name["eth1"]["master"], "br0")
        self.assertEqual(by_name["br0"]["ipv4"][0]["address"], "192.168.1.1")
        self.assertEqual(parse_nvram_keys(b"[NVRAM] 10 lan_ipaddr extra\n"), ["lan_ipaddr"])
        sequence = parse_exec_sequence("[execve-hook] pid=4 exe=/sbin/ubusd\nexecve('/usr/sbin/uhttpd')")
        self.assertEqual([item["executable"] for item in sequence], ["/sbin/ubusd", "/usr/sbin/uhttpd"])

    def test_runtime_filesystem_presence_overrides_disk_only_entries(self):
        snapshot = [
            {"path": "/www/index.html", "kind": "file"},
            {"path": "/www/deleted.html", "kind": "file"},
        ]
        merged = merge_runtime_filesystem(snapshot, "/www\n/www/index.html\n/dev/gpio/in\n")
        self.assertEqual(
            [entry["path"] for entry in merged],
            ["/dev/gpio/in", "/www", "/www/index.html"],
        )


class NetworkPlannerTests(unittest.TestCase):
    def test_prefers_existing_bridge_with_only_link_up_missing(self):
        state = {"network": parse_ip_state(IP_SAMPLE)}
        plan = choose_network_plan(state)
        self.assertEqual(plan["selected"]["mode"], "non_vlan_bridge")
        self.assertEqual(plan["selected"]["ethernet"], "eth1")
        self.assertEqual(plan["selected"]["cost"], 1)
        self.assertEqual(plan["selected"]["tap_tuple"][0], "192.168.1.1")
        self.assertIn("ip link set eth1 up", plan["commands"][0])


class DependencyPlannerTests(unittest.TestCase):
    def test_orders_missing_observed_daemon_before_uhttpd(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary)
            (image / "etc/init.d").mkdir(parents=True)
            (image / "sbin").mkdir()
            (image / "usr/sbin").mkdir(parents=True)
            (image / "etc/init.d/uhttpd").write_text("/sbin/ubusd &\n/usr/sbin/uhttpd\n")
            (image / "sbin/ubusd").write_text("")
            (image / "usr/sbin/uhttpd").write_text("")
            state = {
                "processes": [],
                "exec_sequence": [
                    {"order": 0, "executable": "/sbin/ubusd"},
                    {"order": 1, "executable": "/usr/sbin/uhttpd"},
                ],
            }
            plan = build_ipc_plan(state, image, "/etc/init.d/uhttpd start")
            self.assertEqual(plan["web_binary"], "/usr/sbin/uhttpd")
            self.assertEqual([item["name"] for item in plan["missing_daemons"]], ["ubusd"])

    def test_uses_karonte_upstream_closure_and_dependency_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary)
            (image / "sbin").mkdir()
            (image / "usr/sbin").mkdir(parents=True)
            for path in (image / "sbin/cfgmgr", image / "sbin/ubusd", image / "usr/sbin/uhttpd"):
                path.write_text("")
                path.chmod(0o755)
            bdg = {
                "usable": True,
                "nodes": [
                    {"path": "/sbin/cfgmgr"},
                    {"path": "/sbin/ubusd"},
                    {"path": "/usr/sbin/uhttpd"},
                    {"path": "/sbin/unrelatedd"},
                ],
                "edges": [
                    {"source": "/sbin/cfgmgr", "target": "/sbin/ubusd"},
                    {"source": "/sbin/ubusd", "target": "/usr/sbin/uhttpd"},
                ],
            }
            state = {"processes": [], "exec_sequence": []}
            plan = build_ipc_plan(state, image, "/usr/sbin/uhttpd", bdg=bdg)
            self.assertTrue(plan["bdg_used"])
            self.assertEqual(
                plan["scand"],
                ["/sbin/cfgmgr", "/sbin/ubusd", "/usr/sbin/uhttpd"],
            )
            self.assertEqual(plan["dboot"], ["/sbin/cfgmgr", "/sbin/ubusd"])
            self.assertEqual(plan["dmiss"], ["/sbin/cfgmgr", "/sbin/ubusd"])
            self.assertEqual(
                [item["name"] for item in plan["missing_daemons"]],
                ["cfgmgr", "ubusd"],
            )

    def test_karonte_disable_status_preserves_evidence_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "karonte_bdg.json"
            with patch.dict("os.environ", {"FIRMWELD_KARONTE": "false"}):
                result = run_karonte_bdg(root, "/usr/sbin/uhttpd", output)
            self.assertFalse(result["usable"])
            self.assertEqual(result["status"], "unavailable")
            self.assertTrue(output.is_file())

    def test_karonte_binary_search_treats_firmware_strings_as_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "producer"
            marker = root / "must-not-be-created"
            dangerous = "shared'; touch {}; #".format(marker)
            binary.write_bytes(b"\x7fELF\x00" + dangerous.encode() + b"\x00getenv\x00")
            matches = find_elf_files_containing(root, [dangerous, "getenv"])
            self.assertEqual(matches, [str(binary)])
            self.assertFalse(marker.exists())


class NvramPlannerTests(unittest.TestCase):
    def test_completes_only_additional_keys_from_related_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary)
            (image / "etc").mkdir()
            (image / "etc/defaults.bin").write_bytes(
                b"lan_ipaddr\x00lan_netmask\x00lan_extra_option\x00"
            )
            state = {
                "nvram_keys": ["lan_ipaddr", "lan_netmask"],
                "filesystem": [{"path": "/etc/defaults.bin", "kind": "file"}],
            }
            plan = build_nvram_plan(state, image)
            self.assertIn("lan_extra_option", plan["additional_keys"])
            entry = next(item for item in plan["entries"] if item["key"] == "lan_extra_option")
            self.assertEqual(entry["source"], "empty_fallback")


class ResourceCollectionTests(unittest.TestCase):
    def test_uses_paths_relative_to_detected_webroot(self):
        state = {
            "web_roots": ["/www"],
            "filesystem": [
                {"path": "/www/index.html", "kind": "file"},
                {"path": "/www/js/app.js", "kind": "file"},
                {"path": "/etc/config", "kind": "file"},
            ],
        }
        self.assertEqual(resource_paths(state), ["/index.html", "/js/app.js"])

    def test_collects_runtime_responses_from_observed_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            served = root / "served"
            work = root / "work"
            served.mkdir()
            work.mkdir()
            (served / "index.html").write_text("<html><body>runtime</body></html>")

            class QuietHandler(SimpleHTTPRequestHandler):
                def log_message(self, _format, *args):
                    pass

            handler = lambda *args, **kwargs: QuietHandler(*args, directory=str(served), **kwargs)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                state = {
                    "web_roots": ["/www"],
                    "filesystem": [{"path": "/www/index.html", "kind": "file"}],
                }
                (work / "runtime_state.json").write_text(json.dumps(state))
                (work / "ip").write_text("127.0.0.1\n")
                (work / "web_ports").write_text(str(server.server_port))
                (work / "brand").write_text("test\n")
                (work / "name").write_text("version-1\n")
                manifest = collect(work, work / "web_resources", 2.0, 1, 10)
                self.assertEqual(manifest["collected_count"], 1)
                self.assertTrue((work / "web_resources/pages/index.html").is_file())
                destination, count = export(
                    work / "web_resources/manifest.json", root / "deepfw_dataset"
                )
                self.assertEqual(count, 1)
                self.assertTrue((destination / "index.html").is_file())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class WebVisibilityTests(unittest.TestCase):
    def test_adds_fallback_links_and_scoped_utility_wrappers(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary)
            (image / "www/js").mkdir(parents=True)
            (image / "www/index.html").write_text("<html>ok</html>")
            state = {
                "web_roots": ["/www"],
                "filesystem": [
                    {"path": "/www", "kind": "directory"},
                    {"path": "/www/index.html", "kind": "file"},
                    {"path": "/www/js", "kind": "directory"},
                ],
            }
            plan = build_visibility_plan(state, image, "/usr/sbin/httpd")
            apply_visibility_plan(image, plan)
            self.assertTrue((image / "index.html").is_symlink())
            self.assertTrue((image / "firmadyne/wrapper-bin/rm").is_file())


if __name__ == "__main__":
    unittest.main()
