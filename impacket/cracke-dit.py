import sys, glob, os, argparse, itertools, time
from threading import Thread, Event

import json
import unicodecsv as csv

from examples.secretsdump import NTDSHashes
import re
import codecs
import locale

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
        sys.exit(1)
    
    print('Here')
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
            data.append(displayname.strip())
            data.append(samaccountname.strip())
            data.append(objectguid.strip())
            print(data)
            writer.writerow(data)
