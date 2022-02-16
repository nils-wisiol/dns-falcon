import json
import logging
import os
import subprocess
from typing import Set, Tuple

import dns.dnssec
import dns.name
import dns.rrset
import requests

# requirements: dnspython, requests

IN = dns.rdataclass.from_text("IN")
DS = dns.rdatatype.from_text("DS")
NS = dns.rdatatype.from_text("NS")

DEFAULT_ALGORITHM = "ecdsa256"
SUPPORTED_ALGORITHMS = {
    5: "rsasha1", 8: "rsasha256", 10: "rsasha512",  # pdns also supports 7: "rsasha1-nsec3-sha1",
    13: "ecdsa256", 14: "ecdsa384",
    15: "ed25519", 16: "ed448",
    17: "falcon",
}


def run(args, stdin: str = None) -> Tuple[str, str]:
    logging.debug(f"Running {args}")
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, input=stdin)
    logging.info(f"stdout: {result.stdout}")
    return result.stdout, result.stderr


def auth(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "auth", "pdnsutil") + args)
    return stdout


def recursor(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "recursor", "rec_control") + args)
    return stdout


def add_zone(name: dns.name.Name, algorithm: str, nsec: int = 1):
    assert nsec in {1, 3}
    auth("create-zone", name.to_text())
    if nsec == 3:
        auth("set-nsec3", name.to_text())
    for subname in ["@", "*"]:
        auth("add-record", name.to_text(), subname, "A", "127.0.0.1")
        auth("add-record", name.to_text(), subname, "A", "127.0.0.2")
        auth("add-record", name.to_text(), subname, "AAAA", "::1")
        auth("add-record", name.to_text(), subname, "TXT",
             "\"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon\"")
    if algorithm.startswith('rsa'):
        auth("add-zone-key", name.to_text(), "2048", "active", algorithm)
    else:
        auth("add-zone-key", name.to_text(), "active", algorithm)


def get_ds(name: dns.name.Name):
    def remove_prefix(s, prefix):
        return s[s.startswith(prefix) and len(prefix):]

    pdns_lines = auth("export-zone-ds", name.to_text()).strip().split("\n")
    ds_texts = [
        # remove extra information from pdnsutil output
        remove_prefix(
            remove_prefix(
                remove_prefix(
                    line,
                    name.to_text()  # first remove the name
                ).lstrip(),
                'IN',  # then remove the IN
            ).lstrip(),
            'DS'  # then remove the DS
        ).lstrip().split(';')[0].strip()  # then remove the trailing comment
        for line in pdns_lines
    ]

    try:
        return dns.rrset.from_text_list(name, 0, IN, DS, ds_texts)
    except dns.exception.SyntaxError:
        n = '\n'
        logging.debug(f"Could not obtain DS records for {name.to_text()}. "
                      f"pdns output was \n\n{n.join(pdns_lines)}\n\ndnspython input was\n\n{n.join(ds_texts)}")
        raise


def set_trustanchor_recursor(name: dns.name.Name):
    ds_set = get_ds(name)
    for ds in ds_set:
        recursor("add-ta", name.to_text(), ds.to_text())


def _delegate_set_ns_records(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    if not zone.is_subdomain(parent):
        raise ValueError(f"Given zone {zone} is not a subdomain of given parent {parent}.")
    subname = zone - parent
    ns = dns.name.Name(('ns',)) + subname + parent
    for ns_ip4 in ns_ip4_set:
        auth('add-record', zone.to_text(), 'ns', 'A', ns_ip4)
    for ns_ip6 in ns_ip6_set:
        auth('add-record', zone.to_text(), 'ns', 'AAAA', ns_ip6)
    auth('add-record', zone.to_text(), '@', 'NS', ns.to_text())
    return ns


def delegate_auth(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    ns = _delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    subname = zone - parent
    auth('add-record', parent.to_text(), subname.to_text(), 'NS', ns.to_text())
    ds_set = get_ds(zone)
    for ds in ds_set:
        auth('add-record', parent.to_text(), subname.to_text(), 'DS', ds.to_text())


def delegate_desec(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    ns = _delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    data = json.dumps([
        {
            'subname': (ns - parent).to_text(),
            'ttl': 60,
            'type': 'A',
            'records': list(ns_ip4_set),
        },
        {
            'subname': (ns - parent).to_text(),
            'ttl': 60,
            'type': 'AAAA',
            'records': list(ns_ip6_set),
        },
        {
            'subname': (zone - parent).to_text(),
            'ttl': 60,
            'type': 'NS',
            'records': [ns.to_text()],
        },
        {
            'subname': (zone - parent).to_text(),
            'ttl': 60,
            'type': 'DS',
            'records': [rr.to_text() for rr in get_ds(zone)],
        },
    ], indent=4)
    logging.debug(f"Sending to deSEC:\n\n{data}\n\n")
    response = requests.patch(
        url=f"https://desec.io/api/v1/domains/{parent.to_text().rstrip('.')}/rrsets/",
        headers={
            'Authorization': f'Token {os.environ["DESEC_TOKEN"]}',
            'Content-Type': 'application/json',
        },
        data=data
    )
    if response.status_code not in {200, 201, 204}:
        raise Exception(f"Unexpected response with code {response.status_code}: {response.content}")


def add_test_setup(parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    add_zone(parent, DEFAULT_ALGORITHM)

    for nsec in [1, 3]:
        for algorithm in SUPPORTED_ALGORITHMS.values():
            classic_example = dns.name.Name((algorithm + ('3' if nsec == 3 else ''),)) + parent
            add_zone(classic_example, algorithm, nsec)
            delegate_auth(classic_example, parent, ns_ip4_set, ns_ip6_set)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    local_example = dns.name.Name(("example", ""))
    local_ns_ip4 = "172.20.53.101"
    add_test_setup(local_example, {local_ns_ip4}, set())
    set_trustanchor_recursor(local_example)

    global_name = os.environ.get('DESEC_DOMAIN')
    if global_name:
        global_parent = dns.name.from_text(global_name)
        global_example = dns.name.Name(("example",)) + global_parent
        global_ns_ip4_set = set(filter(bool, os.environ.get('PUBLIC_IP4_ADDRESSES', '').split(',')))
        global_ns_ip6_set = set(filter(bool, os.environ.get('PUBLIC_IP6_ADDRESSES', '').split(',')))
        if not global_ns_ip4_set and not global_ns_ip6_set:
            raise ValueError("At least one public IP address needs ot be supplied.")
        add_test_setup(global_example, global_ns_ip4_set, global_ns_ip6_set)
        delegate_desec(global_example, global_parent, global_ns_ip4_set, global_ns_ip6_set)

    auth('rectify-all-zones')
