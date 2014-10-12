#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
"""
port_service_lookup
"""
from collections import OrderedDict
import logging

SERVICE_FILE = '/usr/share/nmap/nmap-services'

def parse_nmap_services(service_file=SERVICE_FILE):
    service_dict = OrderedDict()
    with open(service_file,'r') as f:
        for l in f:
            if l.lstrip().startswith('#'):
                continue
            service, port = l.split('\t')[:2]
            if port in service_dict:
                print('overlapping')
            service_dict[port] = service
    return service_dict
services = parse_nmap_services()

def port_service_lookup(port, type='tcp', services=services):
    if '/' in port:
        port, type = port.split('/',1)
    key = '/'.join((str(port), type))
    logging.debug(repr(key))
    return services.get(key)

def service_lookup(pattern, services=services):
    logging.debug(repr(pattern))
    for port, service in services.iteritems():
        if pattern.lower() in service.lower():
            yield (port, service)


import unittest
class Test_port_service_lookup(unittest.TestCase):
    def test_port_service_lookup(self):
        _testdata = (
            (('22',), 'ssh'),
            (('53','udp'), 'domain'),
            (('53/udp',), 'domain'),
        )
        for i,o in _testdata:
            result = port_service_lookup(*i)
            self.assertEqual(result, o)


def main():
    import logging
    import optparse
    import sys

    prs = optparse.OptionParser(usage="./%prog : args")

    prs.add_option('-l', '--lookup-service-by-name',
                   dest='lookup_by_name',
                   action='store',)

    prs.add_option('-v', '--verbose',
                    dest='verbose',
                    action='store_true',)
    prs.add_option('-q', '--quiet',
                    dest='quiet',
                    action='store_true',)
    prs.add_option('-t', '--test',
                    dest='run_tests',
                    action='store_true',)

    (opts, args) = prs.parse_args()

    if not opts.quiet:
        logging.basicConfig()

        if opts.verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    if opts.run_tests:
        import sys
        sys.argv = [sys.argv[0]] + args
        import unittest
        exit(unittest.main())

    if opts.lookup_by_name:
        for result in service_lookup(opts.lookup_by_name):
            print(result)
        sys.exit(0)

    print(port_service_lookup(*args[:2]))

if __name__ == "__main__":
    main()
