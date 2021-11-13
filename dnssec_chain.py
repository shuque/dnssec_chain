#!/usr/bin/env python3
#

"""
Tools for querying and building a DNSSEC chain, suitable for use with
RFC 9102 (TLS DNSSEC Chain Extension). Work in progress.

Author: Shumon Huque
"""

import os
import sys
import time
import math
import struct
import argparse
from io import BytesIO
import dns.resolver
import dns.name
import dns.rdatatype
import dns.rcode
import dns.wire


__version__ = "0.1.0"
__description__ = f"""\
Version {__version__}
Generate DNSSEC authentication chain for given qname and qtype."""


RESOLVER_LIST = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

# Default RFC9102 Extension Support Lifetime (in hours; 30 days)
DEFAULT_LIFETIME = 720


class DnssecChainError(Exception):
    """DnssecChainError Class"""


def process_arguments(arguments=None):
    """Process command line arguments"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__description__,
        allow_abbrev=False)
    parser.add_argument("qname", help="DNS query name")
    parser.add_argument("qtype", help="DNS query type")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase output verbosity")
    parser.add_argument("--test", dest='test', action='store_true',
                        help="Test: generate and parse chain data")
    parser.add_argument("--rfc9102", dest='rfc9102', action='store_true',
                        help="Output RFC9102 binary data")
    parser.add_argument("--lifetime", type=int, metavar='<N>',
                        default=DEFAULT_LIFETIME,
                        help="RFC9102 Extension Support Lifetime (default: %(default)d hrs)")
    parser.add_argument("--outform", dest='outform', default='summary',
                        help="Specify output format (default: summary)",
                        choices=['summary', 'full', 'binary'])
    if arguments is not None:
        return parser.parse_args(args=arguments)
    return parser.parse_args()


def get_resolver(addresses=None, lifetime=5, payload=1420):
    """
    Return resolver object configured to use given list of addresses, and
    that sets DO=1, RD=1, AD=1, and EDNS payload for queries to the resolver.
    """

    resolver = dns.resolver.Resolver()
    resolver.set_flags(dns.flags.RD | dns.flags.AD)
    resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=payload)
    resolver.lifetime = lifetime
    if addresses is not None:
        resolver.nameservers = addresses
    return resolver


def is_authenticated(msg):
    """Does DNS message have Authenticated Data (AD) flag set?"""
    return msg.flags & dns.flags.AD == dns.flags.AD


class SignedRRset:
    """Class to hold an RRset and associated signatures if any"""

    def __init__(self, rrname, rrtype, rrset=None, rrsig=None):
        self.rrname = rrname
        self.rrtype = rrtype
        self.rrset = rrset if rrset else None
        self.rrsig = rrsig if rrsig else None

    def set_rrsig(self, rrsig):
        """Set rrsig"""
        self.rrsig = rrsig

    def set_rrset(self, rrset):
        """Set rrset"""
        self.rrset = rrset

    def add_rrsig_rdata(self, rdata, ttl=None):
        """Add RRSIG rdata"""
        self.rrsig.add(rdata, ttl)

    def add_rrset_rdata(self, rdata, ttl=None):
        """Add RRSET rdata"""
        self.rrset.add(rdata, ttl)

    def __repr__(self):
        return "SignedRRset: {}/{}".format(self.rrname,
                                           dns.rdatatype.to_text(self.rrtype))


def get_signed_rrset(msg, qname, qtype):
    """
    get_signed_answer_from_message.
    Returns rrset, rrsigset and signer name.
    """
    rrset = msg.get_rrset(msg.answer,
                          qname,
                          dns.rdataclass.IN,
                          qtype)
    if rrset is None:
        return None, None, None
    rrsigset = msg.get_rrset(msg.answer,
                             qname,
                             dns.rdataclass.IN,
                             dns.rdatatype.RRSIG,
                             covers=qtype)
    if rrsigset is None:
        return rrset, None, None
    signer_list = []
    for record in rrsigset:
        signer_list.append(record.signer)
    if len(signer_list) > 1:
        raise DnssecChainError("Multiple signers for {}/{}: {}".format(
            qname, qtype, signer_list))
    if len(signer_list) == 0:
        raise DnssecChainError("No signers found for {}/{}".format(
            qname, qtype))

    return rrset, rrsigset, signer_list[0]


def _to_wire(rrset):
    bytestream = BytesIO()
    rrset.to_wire(bytestream)
    return bytestream.getvalue()


def duration2string(duration):
    """
    Return time duration in human readable string form.
    """
    days, remainder = divmod(duration, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, remainder = divmod(remainder, 60)
    return "{}d{}h{}m{}s".format(days, hours, minutes, remainder)


def sig_validity(sig_rr, text=False):
    """
    Return length of signature validity period for given RRSIG RR,
    in seconds, or if text=True, as a human readable string.
    """
    duration = sig_rr.expiration - sig_rr.inception
    if text:
        return duration2string(duration)
    return duration


def sig_expires_in(sig_rr, text=False):
    """
    Return time to expiry of given RRSIG RR in seconds, or if text=True,
    as a human readable string.
    """
    duration = sig_rr.expiration - math.floor(time.time() + 0.5)
    if text:
        return duration2string(duration)
    return duration


class Chain:

    """
    DNSSEC Chain class
    """

    def __init__(self, qname, qtype, resolver=None):
        self.qname = dns.name.from_text(qname)
        self.qtype = dns.rdatatype.from_text(qtype)
        self.resolver = resolver if resolver else get_resolver()
        self.parser = None
        self.signers = []
        self.data = {}                    # (rrname, rrtype) -> SignedRRset
        self.rawdata = None
        self.lifetime = DEFAULT_LIFETIME

    def set_lifetime(self, lifetime):
        """set RFC9102 extension support lifetime (in hours)"""
        self.lifetime = lifetime

    def add_entry(self, qname, qtype, rrset, rrsig, replace=False):
        """add signed RRset entry to chain data dictionary"""

        key = (qname, qtype)
        if key in self.data and not replace:
            return
        self.data[key] = SignedRRset(qname, qtype, rrset=rrset, rrsig=rrsig)

    def add_signer(self, signer):
        """add signer name to signers list if not already present"""

        if signer not in self.signers:
            self.signers.append(signer)

    def query(self, qname, qtype):
        """
        Query given qname and qtype, check that response message is
        authenticated, and if so return the message.
        """

        msg = self.resolver.resolve(qname, qtype).response
        if not is_authenticated(msg):
            raise DnssecChainError("Unauthenticated response {}/{}".format(
                qname, dns.rdatatype.to_text(qtype)))
        return msg

    def get_raw_data(self, rfc9102=False):
        """Return raw binary data for DNSSEC chain"""

        if rfc9102:
            return struct.pack('!H', self.lifetime) + self.rawdata
        return self.rawdata

    def compute_raw_data(self):
        """Compute raw data from currently built chain dictionary"""

        output = b''
        for value in self.data.values():
            output += _to_wire(value.rrset)
            output += _to_wire(value.rrsig)
        return output

    def build(self):
        """Build DNSSEC chain"""

        self.get_initial_answers()
        self.chase_signers()
        self.rawdata = self.compute_raw_data()

    def check_dname(self, msg, qname):
        """
        Check for DNAME; if found, returned synthesized target. Otherwise
        return None.
        """

        candidate = qname.parent()
        while candidate != dns.name.root:
            dname, dname_rrsig, signer = get_signed_rrset(msg,
                                                          candidate,
                                                          dns.rdatatype.DNAME)
            if dname is not None:
                self.add_entry(candidate, dns.rdatatype.DNAME,
                               dname, dname_rrsig)
                self.add_signer(signer)
                dname_target = dname.to_rdataset()[0].target
                try:
                    cname_target = dns.name.Name(
                        qname.relativize(dname.name).labels + dname_target.labels)
                except dns.name.NameTooLong as name_too_long:
                    raise DnssecChainError("DNAME produced too long name") from name_too_long
                return cname_target
            candidate = candidate.parent()
        return None

    def check_cname(self, msg, qname):
        """
        Check for CNAME, following chains as necessary. Return the
        target of the terminal CNAME.
        """

        current_qname = qname
        while True:
            cname, cname_rrsig, signer = get_signed_rrset(msg,
                                                          current_qname,
                                                          dns.rdatatype.CNAME)
            if cname is None or cname_rrsig is None:
                dname_result = self.check_dname(msg, current_qname)
                if dname_result is None:
                    return current_qname
                current_qname = dname_result
                continue
            self.add_entry(current_qname, dns.rdatatype.CNAME,
                           cname, cname_rrsig)
            self.add_signer(signer)
            current_qname = cname[0].target
        return current_qname

    def get_initial_answers(self):
        """
        Fetch initial answer sets following CNAME/DNAME indirections
        if present. (TODO: DNAME processing)
        """

        msg = self.query(self.qname, self.qtype)

        answer, answer_rrsig, signer= get_signed_rrset(msg,
                                                       self.qname,
                                                       self.qtype)
        if answer is not None:
            self.add_entry(self.qname, self.qtype, answer, answer_rrsig)
            self.add_signer(signer)
            return

        cname_target = self.check_cname(msg, self.qname)
        answer, answer_rrsig, signer= get_signed_rrset(msg,
                                                       cname_target,
                                                       self.qtype)
        self.add_entry(cname_target, self.qtype, answer, answer_rrsig)
        self.add_signer(signer)

    def query_rrset(self, qname, qtype):
        """query_rrset"""

        msg = self.query(qname, qtype)
        answer, answer_rrsig, signer = get_signed_rrset(msg, qname, qtype)
        self.add_entry(qname, qtype, answer, answer_rrsig)
        return signer

    def chase_signers(self):
        """Chase signers of top level names and build chain to root"""

        for signer in self.signers:
            current_signer = signer
            while current_signer != dns.name.root:
                if (current_signer, dns.rdatatype.DNSKEY) in self.data:
                    break
                _ = self.query_rrset(current_signer, dns.rdatatype.DNSKEY)
                if (current_signer, dns.rdatatype.DS) in self.data:
                    break
                current_signer = self.query_rrset(current_signer, dns.rdatatype.DS)
            if (dns.name.root, dns.rdatatype.DNSKEY) in self.data:
                break
            _ = self.query_rrset(dns.name.root, dns.rdatatype.DNSKEY)

    @staticmethod
    def add_entry_single_rr(rrset_dict, qname, qtype, rrset):
        """Add single RR entry to chain data dictionary"""

        rdata = rrset.to_rdataset()[0]
        if (qname, qtype) in rrset_dict:
            srrset = rrset_dict[(qname, qtype)]
            if rrset.rdtype == dns.rdatatype.RRSIG:
                if srrset.rrsig is None:
                    srrset.rrsig = rrset
                else:
                    srrset.add_rrsig_rdata(rdata, ttl=rrset.ttl)
            else:
                if srrset.rrset is None:
                    srrset.rrset = rrset
                else:
                    srrset.add_rrset_rdata(rdata, ttl=rrset.ttl)
        else:
            srrset = SignedRRset(qname, qtype)
            if rrset.rdtype == dns.rdatatype.RRSIG:
                srrset.set_rrsig(rrset)
            else:
                srrset.set_rrset(rrset)
            rrset_dict[(qname, qtype)] = srrset

    def parse_single_rr(self):
        """Parse single RR from chain raw data"""

        rrname = self.parser.get_name()
        rrtype = dns.rdatatype.RdataType(self.parser.get_uint16())
        rrclass = self.parser.get_uint16()
        ttl = self.parser.get_uint32()
        rdlen = self.parser.get_uint16()
        rdata_wire = self.parser.get_bytes(rdlen)
        rdata = dns.rdata.from_wire(rrclass,
                                    rrtype,
                                    rdata_wire,
                                    0,
                                    rdlen)
        if rrtype == dns.rdatatype.RRSIG:
            covered_type = rdata.covers()
        else:
            covered_type = rrtype
        rrset = dns.rrset.RRset(rrname, dns.rdataclass.IN, rrtype)
        rrset.ttl = ttl
        rrset.add(rdata)
        return rrname, covered_type, rrset

    def parse(self, rawdata, rfc9102=False):
        """set and parse raw data for a received DNSSEC chain"""

        if rfc9102:
            self.lifetime = struct.unpack('!H', rawdata[:2])
            self.rawdata = rawdata[2:]
        else:
            self.rawdata = rawdata

        # (rrname, rrtype) -> SignedRRset
        rrset_dict = {}

        self.parser = dns.wire.Parser(self.rawdata)
        while self.parser.remaining() > 0:
            rrname, covered_type, rrset = self.parse_single_rr()
            self.add_entry_single_rr(rrset_dict,
                                     rrname,
                                     covered_type,
                                     rrset)
        self.data = rrset_dict

    def validate(self):
        """validate received chain data (not done yet)"""

        _ = self

    def output_summary(self, verbose=False):
        """Print chain record name summary"""

        for key, value in self.data.items():
            rrname, rrtype = key
            print("{} {}".format(rrname, dns.rdatatype.to_text(rrtype)))
            if verbose:
                for record in value.rrsig:
                    print("    {}/{} expires: {} validity: {}".format(
                        record.signer,
                        record.key_tag,
                        sig_expires_in(record, text=True),
                        sig_validity(record, text=True)))

    def output_full(self):
        """Print complete chain records in presentation format"""

        for value in self.data.values():
            print(value.rrset)
            print(value.rrsig)

    def display(self):
        """Print Chain contents"""

        print('CHAIN synopsis:')
        self.output_summary(verbose=True)
        print('\nCHAIN full data:')
        self.output_full()


def same_chain_data(chain1, chain2):
    """Do given chains have the same data?"""

    for key1, key2 in zip(chain1.data, chain2.data):
        if key1 != key2:
            return False

    for value1, value2 in zip(chain1.data.values(), chain2.data.values()):
        if value1.rrset != value2.rrset:
            return False
        if value1.rrsig != value2.rrsig:
            return False
    return True


def print_rfc9102_data(qname, qtype, lifetime):
    """Return binary RFC9102 format chain data"""

    chain = Chain(qname, qtype,
                  resolver=get_resolver(addresses=RESOLVER_LIST))
    chain.set_lifetime(lifetime)
    chain.build()
    sys.stdout.buffer.write(chain.get_raw_data(rfc9102=True))


def print_output(config):
    """Print output according to --outform parameter"""

    chain = Chain(config.qname, config.qtype,
                  resolver=get_resolver(addresses=RESOLVER_LIST))
    chain.set_lifetime(config.lifetime)
    chain.build()
    if config.outform == "summary":
        chain.output_summary(verbose=config.verbose>0)
    elif config.outform == "full":
        chain.output_full()
    elif config.outform == "binary":
        sys.stdout.buffer.write(chain.get_raw_data())


def basic_test(qname, qtype):
    """Perform a basic test"""

    # Configure DNS resolver
    resolver = get_resolver(addresses=RESOLVER_LIST)

    # Build chain data
    print("\n### Build Chain Data")
    chain1 = Chain(qname, qtype, resolver=resolver)
    chain1.build()
    chain1.display()

    # Parse chain data
    print("\n### Parse Chain Data")
    wire_data = chain1.get_raw_data()
    print("Wire format data length: {}".format(len(wire_data)))
    chain2 = Chain(qname, qtype)
    chain2.parse(wire_data)
    chain2.display()

    # Do both chains contain the same data?
    print("\n### Built and parsed chains match?",
          same_chain_data(chain1, chain2))


if __name__ == '__main__':

    PROGNAME = os.path.basename(sys.argv[0])
    CONFIG = process_arguments()
    if CONFIG.test:
        basic_test(CONFIG.qname, CONFIG.qtype)
    elif CONFIG.rfc9102:
        print_rfc9102_data(CONFIG.qname, CONFIG.qtype, CONFIG.lifetime)
    else:
        print_output(CONFIG)
