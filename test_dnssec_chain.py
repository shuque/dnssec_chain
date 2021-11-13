#!/usr/bin/env python3

"""
Tests for dnssec_chain
"""

import unittest
import dns.resolver
from dnssec_chain import (Chain, RESOLVER_LIST, get_resolver,
                          same_chain_data, DnssecChainError)


TEST_VECTORS = [

    # Simple TLSA
    [('_443._tcp.www.huque.com.', 'TLSA'),
     dict(exc=None)],

    # DNAME TLSA
    [('_443._tcp.www.huque.dnskensa.com.', 'TLSA'),
     dict(exc=None)],

    # DNAME to CNAME chain
    [('www.huque.dnskensa.com.', 'A'),
     dict(exc=None)],

    # CNAME to DNAME to CNAME chain
    [('c2d2c.huque.com.', 'A'),
     dict(exc=None)],

    # NODATA
    [('_443._tcp.www.huque.com.', 'A'),
     dict(exc=dns.resolver.NoAnswer)],

    # NXDOMAIN
    [('_443._tcp.princeton.edu.', 'TLSA'),
     dict(exc=dns.resolver.NXDOMAIN)],

    # CNAME chain to child zones
    [('fda.my.salesforce.com.', 'A'),
     dict(exc=None)],

    # Unauthenticated answer
    [('google.com.', 'A'),
     dict(exc=DnssecChainError)],

]


class TestChain(unittest.TestCase):

    """Test class for DNSSEC chain functions"""

    def setUp(self):
        self.resolver = get_resolver(addresses=RESOLVER_LIST)

    def test_all(self):
        """Run tests on all test vectors"""
        count  = 0
        for vector in TEST_VECTORS:
            count += 1
            with self.subTest(vector=vector):
                query, expected_result = vector
                qname, qtype = query
                chain1 = Chain(qname, qtype, resolver=self.resolver)
                if expected_result['exc'] is not None:
                    with self.assertRaises(expected_result['exc']):
                        chain1.build()
                    continue
                chain1.build()
                chain2 = Chain(qname, qtype)
                chain2.parse(chain1.get_raw_data())
                self.assertEqual(same_chain_data(chain1, chain2), True)
        print("Total #subtests: {}".format(count))


if __name__ == '__main__':
    unittest.main()
