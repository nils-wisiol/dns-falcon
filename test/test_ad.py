import dns.flags
import dns.message
import dns.query
from dns.rdatatype import SOA, TXT, RRSIG
from dns.rdataclass import IN


def query(qname, rdtype) -> dns.message.Message:
    q = dns.message.make_query(qname=qname, rdtype=rdtype, want_dnssec=True)
    r, _ = dns.query.udp_with_fallback(q, where='127.0.0.1', port=5302)
    return r


def test_ad():
    assert dns.flags.AD in query("classic.example.", SOA).flags
    assert dns.flags.AD in query("falcon.example.", SOA).flags


def test_has_falcon_rrsig():
    qname = dns.name.from_text("falcon.example.")
    r = query(qname, TXT)
    assert {rr.algorithm for rr in r.find_rrset(dns.message.ANSWER, qname, IN, RRSIG, covers=TXT)} == {17}
