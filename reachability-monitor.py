#!/usr/bin/env python3

from datetime import datetime as dt
from functools import reduce
import json
import logging
from os.path import abspath, dirname, join
from re import findall, search
import socket
import socks
from sockshandler import SocksiPyHandler
import stem
import stem.connection
from stem.control import Controller
import urllib.error
from urllib.request import build_opener, Request, urlopen

class SDMonitor:
    """Does version string checks on SecureDrop instances and prints tor
    circuit debugging information for unreachable instances."""
    def __init__(self):
        self.controller = Controller.from_port()
        self.controller.authenticate() 

        self.tor_version = self.controller.get_version()
        # logger.info("Tor is running version {}".format(self.tor_version))


    def __enter__(self):
        return self


    def __exit__(self, exc_type, exc_value, traceback):
        self.controller.close()


    def read_directory(self, directory_url):
        """Parses the SecureDrop directory into a dictionary of instance
        details."""
        # CloudFlare will block us if we don't set user-agent
        dir_req = Request(directory_url)
        dir_req.add_header("User-Agent", 
                           "Mozilla/5.0 (Windows NT 6.1; rv:45.0) "
                           "Gecko/20100101 Firefox/45.0")
        directory = urlopen(dir_req).read().decode()

        instances = []
        for line in directory.splitlines()[1:-1]:
            fields = line.split("\t")
            instances.append(dict(organization=fields[0],
                                  landing_page=fields[1],
                                  ths_address=fields[2]))

        return instances



    def check_instances(self, instances, timeout=30):
        """Visits each SD found in the directory and records its version
        string or the string 'unreachable', as well as relevant circuit
        information and descriptor information."""
        opener = build_opener(SocksiPyHandler(socks.SOCKS5, "127.0.0.1", 9050))

        for instance in instances:
            hs_url = instance.get("ths_address")

            try:
                response = opener.open("http://"+hs_url,
                                       timeout=timeout).read().decode()
                version_str = search("Powered by SecureDrop [0-9.]+",
                                     response).group(0)
                instance["version"] = version_str.split()[-1][:-1]
            except (socks.SOCKS5Error, socks.GeneralProxyError,
                    urllib.error.URLError):
                instance["version"] = "unreachable"
                try:
                    # The reason that we don't call the
                    # get_hidden_service_descriptor method on all URLs is that
                    # it's unreliable for services that are actually up.
                    # Basically, the method will never return or timeout. With
                    # services that cannot be reached, it usually quickly
                    # fails with the stem.DescriptorUnavailable exception. This
                    # seems to be the leading cause of unreachability.
                    hs_desc = self.controller.get_hidden_service_descriptor(hs_url)
                    instance["intro_pts"] = hs_desc.introduction_points_content.decode()
                except stem.DescriptorUnavailable:
                    instance["intro_pts"] = "descriptor unavailable"
                    print(instance)
                    continue
                pass

            intro_circs = []
            rend_circs = []
            
            for circuit in self.controller.get_circuits():
                if circuit.purpose == "HS_CLIENT_INTRO":
                    intro_circs.append(dict(path=circuit.path,
                                           reason=circuit.reason,
                                           remote_reason=circuit.remote_reason))
                if circuit.purpose == "HS_CLIENT_REND":
                    rend_circs.append(dict(path=circuit.path,
                                           state=circuit.hs_state,
                                           reason=circuit.reason,
                                           remote_reason=circuit.remote_reason))
                self.controller.close_circuit(circuit.id)

            instance["intro_circs"] = intro_circs
            instance["rend_circs"] = rend_circs

            if instance["version"] == "unreachable":
                print(instance)

        return instances



if __name__ == "__main__":
    directory_url = "https://securedrop.org/sites/securedrop.org/files/securedrop_list.txt"
    logdir = join(dirname(abspath(__file__)), "logs")
    time = dt.now().strftime('%m-%d_%H:%M:%S')
    results_file = "results_" + time + ".json"
    logfile = "sdrm_" + time + ".log"

    logger = logging.basicConfig(level=logging.INFO, 
                                 filename=join(logdir, logfile),
                                 format="%(asctime)s %(message)s",
                                 datefmt="%H:%M:%S")

    with SDMonitor() as sdmonitor:
        instances = sdmonitor.read_directory(directory_url)
        instances = sdmonitor.check_instances(instances)

    with open(join(logdir, results_file ), "w") as fh:
        json.dump(instances, fh)
