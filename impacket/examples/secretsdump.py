# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Performs various techniques to dump hashes from the
#              remote machine without executing any agent there.
#              For SAM and LSA Secrets (including cached creds)
#              we try to read as much as we can from the registry
#              and then we save the hives in the target system
#              (%SYSTEMROOT%\\Temp dir) and read the rest of the
#              data from there.
#              For NTDS.dit we either:
#                a. Get the domain users list and get its hashes
#                   and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#                   call, replicating just the attributes we need.
#                b. Extract NTDS.dit via vssadmin executed  with the
#                   smbexec approach.
#                   It's copied on the temp dir and parsed remotely.
#
#              The script initiates the services required for its working
#              if they are not available (e.g. Remote Registry, even if it is 
#              disabled). After the work is done, things are restored to the 
#              original state.
#
# Author:
#  Alberto Solino (@agsolino)
#
# References: Most of the work done by these guys. I just put all
#             the pieces together, plus some extra magic.
#
# https://github.com/gentilkiwi/kekeo/tree/master/dcsync
# http://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
# http://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
# http://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
# http://www.quarkslab.com/en-blog+read+13
# https://code.google.com/p/creddump/
# http://lab.mediaservice.net/code/cachedump.rb
# http://insecurety.net/?p=768
# http://www.beginningtoseethelight.org/ntsecurity/index.htm
# http://www.ntdsxtract.com/downloads/ActiveDirectoryOfflineHashDumpAndForensics.pdf
# http://www.passcape.com/index.php?section=blog&cmd=details&id=15
#
import logging
import string

from ese import ESENT_DB
from ese import LOG

class NTDSHashes:
    class SECRET_TYPE:
        NTDS = 0
        NTDS_CLEARTEXT = 1
        NTDS_KERBEROS = 2
        
    NAME_TO_INTERNAL = {
        'uSNCreated':'ATTq131091',
        'uSNChanged':'ATTq131192',
        'name':'ATTm3',
        'objectGUID':'ATTk589826',
        'objectSid':'ATTr589970',
        'userAccountControl':'ATTj589832',
        'primaryGroupID':'ATTj589922',
        'accountExpires':'ATTq589983',
        'logonCount':'ATTj589993',
        'sAMAccountName':'ATTm590045',
        'sAMAccountType':'ATTj590126',
        'lastLogonTimestamp':'ATTq589876',
        'userPrincipalName':'ATTm590480',
        'unicodePwd':'ATTk589914',
        'dBCSPwd':'ATTk589879',
        'ntPwdHistory':'ATTk589918',
        'lmPwdHistory':'ATTk589984',
        'pekList':'ATTk590689',
        'supplementalCredentials':'ATTk589949',
        'pwdLastSet':'ATTq589920',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)
   
    def __init__(self, ntdsFile, isRemote=False):
        self.__NTDS = ntdsFile
        try:
            if self.__NTDS is not None:
                self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
                self.__cursor = self.__ESEDB.openTable('datatable')
        except Exception as e:
            LOG.error('Error opening the file')
            raise e
            
    def getNextRecord(self):
        record = self.__ESEDB.getNextRow(self.__cursor)
        if record is None:
            return None, False
        elif self.NAME_TO_INTERNAL['sAMAccountType'] not in record:
            raise Exception('InvalidFile')
        try:
            if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                if record[self.NAME_TO_INTERNAL['sAMAccountName']] is not None:
                    userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
                else:
                    userName = 'N/A'
                    return None, True
                if record[self.NAME_TO_INTERNAL['name']] is not None:
                    displayName = '%s' % record[self.NAME_TO_INTERNAL['name']]
                else:
                    displayName = 'N/A'
                    return None, True
                if record[self.NAME_TO_INTERNAL['objectGUID']] is not None:
                    objectGuid = '%s' % record[self.NAME_TO_INTERNAL['objectGUID']]
                else:
                    objectGuid = 'N/A'
                    return None, True
                fields = "%s:%s:%s" % (displayName, userName, objectGuid)
                return fields, True
            else:
                return None, True
        except Exception as e:
            LOG.error(e)            
            raise Exception('Fetching of next record failed')

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()
