import logging
import subprocess

import dns.dnssec
import dns.name
import dns.rrset

# requirements: dnspython, requests

IN = dns.rdataclass.from_text("IN")
DS = dns.rdatatype.from_text("DS")
NS = dns.rdatatype.from_text("NS")


def run(args, stdin: str = None) -> str:
    logging.debug(f"Running {args}")
    stdout = subprocess.run(args, stdout=subprocess.PIPE, text=True, input=stdin).stdout
    logging.info(f"stdout: {stdout}")
    return stdout


def auth(*args) -> str:
    return run(("docker-compose", "exec", "auth", "pdnsutil") + args)


def recursor(*args) -> str:
    return run(("docker-compose", "exec", "recursor", "rec_control") + args)


def add_zone(name: dns.name.Name):
    auth("create-zone", name.to_text())
    auth("add-record", name.to_text(), "@", "A", "127.0.0.1")
    auth("add-record", name.to_text(), "@", "A", "127.0.0.2")
    auth("add-record", name.to_text(), "@", "AAAA", "::1")
    auth("add-record", name.to_text(), "@", "TXT", "\"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon\"")


def add_zone_classic(name: dns.name.Name):
    add_zone(name)
    auth("secure-zone", name.to_text())


def add_zone_falcon(name: dns.name.Name):
    add_zone(name)
    auth("add-zone-key", name.to_text(), "active", "falcon")


def get_ds(name: dns.name.Name):
    ds_texts = [
        # remove extra information from pdnsutil output
        line.removeprefix(name.to_text()).lstrip().removeprefix(
            'IN').lstrip().removeprefix('DS').lstrip().split(';')[0].strip()
        for line in auth("export-zone-ds", name.to_text()).strip().split("\n")
    ]
    return dns.rrset.from_text_list(name, 0, IN, DS, ds_texts)


def set_trustanchor(name: dns.name.Name):
    ds_set = get_ds(name)
    for ds in ds_set:
        recursor("add-ta", name.to_text(), ds.to_text())


def delegate(zone: dns.name.Name, parent: dns.name.Name, ns_ip4: str):
    if not zone.is_subdomain(parent):
        raise ValueError(f"Given zone {zone} is not a subdomain of given parent {parent}.")
    subname = zone - parent
    ns = dns.name.Name(('ns',)) + subname + parent
    auth('add-record', zone.to_text(), 'ns', 'A', ns_ip4)
    auth('add-record', zone.to_text(), '@', 'NS', ns.to_text())
    auth('add-record', parent.to_text(), subname.to_text(), 'NS', ns.to_text())
    ds_set = get_ds(zone)
    for ds in ds_set:
        auth('add-record', parent.to_text(), subname.to_text(), 'DS', ds.to_text())


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, force=True)

    example = dns.name.Name(("example", ""))
    add_zone_classic(example)
    set_trustanchor(example)

    classic_example = dns.name.Name(("classic",)) + example
    add_zone_classic(classic_example)
    delegate(classic_example, example, "172.20.53.101")

    falcon_example = dns.name.Name(("falcon",)) + example
    add_zone_falcon(falcon_example)
    delegate(falcon_example, example, "127.20.53.101")

    auth('rectify-all-zones')
