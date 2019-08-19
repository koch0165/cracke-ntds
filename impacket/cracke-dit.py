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
    group.add_argument("--samaccounttypes", action="store", help="Sam Account types that need to be parsed. This is a bit flag")
    args, unknown_args = parser.parse_known_args()
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout) 

    try:
        ntdshashes = NTDSHashes(args.ntds, args.samaccounttypes)
    except Exception as e:
        LOG.error(e)
        sys.exit(1)
    
    LOG.info("Start of parsing of the NTDS.DIT")
    numObjects = 0
    myFile = open(args.out, 'w')
    with myFile:
        myFields = ['name', 'sam_account_name', 'distinguished_name', 'object_type', 'guid']
        writer = csv.writer(myFile)
        while True:
            record, hasNextRecord = ntdshashes.getNextRecord()
            if hasNextRecord == False:
                break
            if record is None:
                continue
            data = []
            try:
                data.append(record['name'].strip().encode("utf-8"))
                data.append(record['samAccountName'].strip().encode("utf-8"))
                data.append(record['dnName'].strip().encode("utf-8"))
                data.append(record['objectType'].strip().encode('utf-8'))
                data.append(record['guid'].strip().encode("utf-8"))
                data.append(record['email'].strip().encode("utf-8"))
                LOG.debug(data)
                writer.writerow(data)
                numObjects = numObjects + 1
            except Exception as e:
                LOG.error(e)   
    LOG.info('The number of objects present in the NTDS.DIT are %d ', numObjects)
    if numObjects == 0:
        LOG.error('The NTDS.DIT file has no AD objects.')
        sys.exit(1)
    LOG.info("Parsing of the NTDS.DIT is completed")
