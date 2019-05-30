import sys, glob, os, argparse, itertools, time
from threading import Thread, Event

import json
import csv

from examples.secretsdump import NTDSHashes
import re
import codecs
import locale
import logging

from ese import LOG

if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False, description="crack-dit makes it easier to perform password "
                                                                "audits against Windows-based corporate environments.",
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    group = parser.add_argument_group("1. Cracking", "cracke-dit can take your raw ntds.dit and SYSTEM hive "
                                                              "and turn them in to a user:hash file for cracking "
                                                              "within your favourite password cracker")
    group.add_argument("--ntds", action="store", help="(local) ntds.dit file to parse")
    group.add_argument("--out", action="store", help="File to write user:hash to")
    args, unknown_args = parser.parse_known_args()
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout) 

    try:
        ntdshashes = NTDSHashes(args.ntds)
    except Exception as e:
        LOG.error(e)
        sys.exit(1)
    
    LOG.info("Start of parsing of the NTDS.DIT")
    myFile = open(args.out, 'w')
    with myFile:
        myFields = ['name', 'sam_account_name','guid']
        writer = csv.writer(myFile)
        while True:
            record, hasNextRecord = ntdshashes.getNextRecord()
            if hasNextRecord == False:
                break
            if record is None:
                continue
            displayname, samaccountname, objectguid  = re.findall("(?P<displayname>.*):(?P<user>.*):(?P<objectguid>.*)", record)[0]
            data = []
            data.append(displayname.strip().encode("utf-8"))
            data.append(samaccountname.strip().encode("utf-8"))
            data.append(objectguid.strip().encode("utf-8"))
            LOG.info(data)
            writer.writerow(data)
