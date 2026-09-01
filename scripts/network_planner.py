#!/usr/bin/env python3
"""Infer the lowest-cost network intervention from a runtime snapshot."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from runtime_state import write_json_atomic


@dataclass
class Candidate:
    mode: str
    ethernet: str
    vlan: str | None
    bridge: str | None
    address_interface: str
    missing_up: list[str]
    missing_relations: list[tuple[str, str]]
    missing_ip: bool
    cost: int = 0


def _interfaces(state: dict) -> dict[str, dict]:
    return {
        item["name"]: item
        for item in state.get("network", {}).get("interfaces", [])
        if item.get("name")
    }


def _valid_ipv4(item: dict | None) -> str | None:
    if not item:
        return None
    for value in item.get("ipv4", []):
        address = value.get("address")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_loopback and not parsed.is_link_local and address != "0.0.0.0":
            return address
    return None


def _vlan_id(name: str) -> int | None:
    match = re.match(r"^vlan(\d+)$", name, re.IGNORECASE)
    if not match:
        match = re.search(r"\.(\d+)$", name)
    return int(match.group(1)) if match else None


def _preferred_default_ip(interfaces: dict[str, dict]) -> str:
    for item in interfaces.values():
        address = _valid_ipv4(item)
        if not address:
            continue
        try:
            if ipaddress.ip_address(address).is_private:
                return address
        except ValueError:
            pass
    return "192.168.0.1"


def enumerate_candidates(state: dict, weights: dict[str, int]) -> list[Candidate]:
    interfaces = _interfaces(state)
    ethernets = [item for item in interfaces.values() if item.get("type") == "ethernet"]
    if not ethernets:
        ethernets = [item for item in interfaces.values() if item["name"].startswith("eth")]
    bridges = [item for item in interfaces.values() if item.get("type") == "bridge"]
    vlans = [item for item in interfaces.values() if item.get("type") == "vlan"]

    if not ethernets:
        ethernets = [{
            "name": "eth0", "up": False, "master": None, "lower": None,
            "ipv4": [], "mac": None, "type": "ethernet",
        }]
    bridge_options = bridges or [{
        "name": "br0", "up": False, "master": None, "lower": None,
        "ipv4": [], "mac": None, "type": "bridge", "synthetic": True,
    }]

    candidates = []

    def add(mode, ethernet, vlan, bridge, address_interface, relations):
        involved = [ethernet]
        if vlan:
            involved.append(vlan)
        if bridge:
            involved.append(bridge)
        missing_up = [name for name in involved if not interfaces.get(name, {}).get("up", False)]
        missing_relations = []
        for child, parent in relations:
            child_item = interfaces.get(child, {})
            parent_is_bridge = (
                parent == bridge
                or interfaces.get(parent, {}).get("type") == "bridge"
            )
            actual_parent = child_item.get("master") if parent_is_bridge else child_item.get("lower")
            if actual_parent != parent:
                missing_relations.append((child, parent))
        missing_ip = _valid_ipv4(interfaces.get(address_interface)) is None
        candidate = Candidate(
            mode=mode,
            ethernet=ethernet,
            vlan=vlan,
            bridge=bridge,
            address_interface=address_interface,
            missing_up=missing_up,
            missing_relations=missing_relations,
            missing_ip=missing_ip,
        )
        candidate.cost = (
            weights["up"] * len(missing_up)
            + weights["relation"] * len(missing_relations)
            + weights["ip"] * int(missing_ip)
        )
        candidates.append(candidate)

    for ethernet in ethernets:
        eth_name = ethernet["name"]
        add("non_vlan_direct", eth_name, None, None, eth_name, [])
        for bridge in bridge_options:
            br_name = bridge["name"]
            add("non_vlan_bridge", eth_name, None, br_name, br_name, [(eth_name, br_name)])
        for vlan in vlans:
            vlan_name = vlan["name"]
            if vlan.get("lower") is None and not vlan_name.startswith(eth_name + "."):
                continue
            if vlan.get("lower") not in (None, eth_name) and not vlan_name.startswith(eth_name + "."):
                continue
            add("vlan_direct", eth_name, vlan_name, None, vlan_name, [(vlan_name, eth_name)])
            for bridge in bridge_options:
                br_name = bridge["name"]
                add(
                    "vlan_bridge", eth_name, vlan_name, br_name, br_name,
                    [(vlan_name, eth_name), (vlan_name, br_name)],
                )
    return candidates


def _commands(candidate: Candidate, state: dict, address: str) -> list[str]:
    interfaces = _interfaces(state)
    commands = []

    def quoted(value):
        return shlex.quote(value)

    if candidate.bridge and candidate.bridge not in interfaces:
        commands.append(f"/firmadyne/busybox brctl addbr {quoted(candidate.bridge)}")

    for name in candidate.missing_up:
        commands.append(f"/firmadyne/busybox ip link set {quoted(name)} up")

    for child, parent in candidate.missing_relations:
        if candidate.vlan == child and parent == candidate.ethernet:
            vlan_id = _vlan_id(child)
            if child not in interfaces and vlan_id is not None:
                commands.append(
                    f"/firmadyne/busybox ip link add link {quoted(parent)} "
                    f"name {quoted(child)} type vlan id {vlan_id}"
                )
        elif parent == candidate.bridge:
            commands.append(f"/firmadyne/busybox brctl addif {quoted(parent)} {quoted(child)}")

    if candidate.missing_ip:
        commands.append(
            f"/firmadyne/busybox ip addr add {quoted(address)}/24 "
            f"dev {quoted(candidate.address_interface)}"
        )
    return commands


def choose_network_plan(
    state: dict,
    weights: dict[str, int] | None = None,
) -> dict:
    weights = weights or {"up": 1, "relation": 2, "ip": 4}
    candidates = enumerate_candidates(state, weights)
    if not candidates:
        raise ValueError("No network candidate could be generated")

    mode_preference = {
        "non_vlan_direct": 0,
        "non_vlan_bridge": 1,
        "vlan_direct": 2,
        "vlan_bridge": 3,
    }
    selected = min(
        candidates,
        key=lambda item: (
            item.cost,
            len(item.missing_relations),
            int(item.missing_ip),
            mode_preference[item.mode],
            item.ethernet,
        ),
    )
    interfaces = _interfaces(state)
    address = _valid_ipv4(interfaces.get(selected.address_interface)) or _preferred_default_ip(interfaces)
    mac = interfaces.get(selected.ethernet, {}).get("mac")
    vlan_id = _vlan_id(selected.vlan) if selected.vlan else None
    tap_tuple = [
        address,
        selected.ethernet,
        vlan_id,
        mac,
        selected.bridge or selected.address_interface,
    ]
    return {
        "schema_version": 1,
        "weights": weights,
        "selected": {
            "mode": selected.mode,
            "cost": selected.cost,
            "ethernet": selected.ethernet,
            "vlan": selected.vlan,
            "bridge": selected.bridge,
            "address_interface": selected.address_interface,
            "address": address,
            "tap_tuple": tap_tuple,
        },
        "unsatisfied": {
            "up": selected.missing_up,
            "relations": [list(value) for value in selected.missing_relations],
            "ip": selected.missing_ip,
        },
        "commands": _commands(selected, state, address),
        "candidates": [
            {
                "mode": item.mode,
                "ethernet": item.ethernet,
                "vlan": item.vlan,
                "bridge": item.bridge,
                "address_interface": item.address_interface,
                "cost": item.cost,
            }
            for item in sorted(candidates, key=lambda value: (value.cost, value.mode, value.ethernet))
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal FirmWELD network intervention")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--weight-up", type=int, default=1)
    parser.add_argument("--weight-relation", type=int, default=2)
    parser.add_argument("--weight-ip", type=int, default=4)
    args = parser.parse_args()
    with args.state.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    plan = choose_network_plan(state, {
        "up": args.weight_up,
        "relation": args.weight_relation,
        "ip": args.weight_ip,
    })
    output = args.output or args.state.with_name("network_intervention.json")
    write_json_atomic(output, plan)
    print(f"Saved network intervention to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
