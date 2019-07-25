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
from collections import defaultdict

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
        'distinguishedName':'DN', #The DN is custom tag.
        'displayName':'ATTm589825' #This is the name used as part of distinguished name.
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_USER_OBJECT         = 0x30000000
    SAM_TRUST_ACCOUNT       = 0x30000002
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_GROUP_OBJECT        = 0x10000000
    SAM_NON_SECURITY_GROUP_OBJECT = 0x10000001
    SAM_ALIAS_OBJECT        = 0x20000000
    SAM_NON_SECURITY_ALIAS_OBJECT = 0x20000001

    SAM_ACCOUNT_TYPE_TO_OBJECT_CLASS = {
        SAM_NORMAL_USER_ACCOUNT:'user',
        SAM_USER_OBJECT:'user',
        SAM_TRUST_ACCOUNT:'user',
        SAM_MACHINE_ACCOUNT:'computer',
        SAM_GROUP_OBJECT:'group',
        SAM_NON_SECURITY_GROUP_OBJECT:'group',
        SAM_ALIAS_OBJECT:'group',
        SAM_NON_SECURITY_ALIAS_OBJECT:'group',
    }
  
    FLAG_TO_ACCOUNT_TYPES = {
        1:SAM_NORMAL_USER_ACCOUNT,
        2:SAM_USER_OBJECT,
        4:SAM_TRUST_ACCOUNT,
        8:SAM_MACHINE_ACCOUNT,
        16:SAM_GROUP_OBJECT,
        32:SAM_NON_SECURITY_GROUP_OBJECT,
        64:SAM_ALIAS_OBJECT,
        128:SAM_NON_SECURITY_ALIAS_OBJECT,
    }
   
    def __init__(self, ntdsFile, samAccountTypes, isRemote=False):
        self.__NTDS = ntdsFile
        self.__ACCOUNT_TYPES = set()
        flagVal = 1
        bitFlag = 1
        self.__fetchOU = False
        samAccountTypes = int(samAccountTypes)

        while samAccountTypes > 0:
            if samAccountTypes & bitFlag > 0:
                if flagVal == 256:
                    self.__fetchOU = True
                else:
                    self.__ACCOUNT_TYPES.add(self.FLAG_TO_ACCOUNT_TYPES[flagVal])
                # Rightshift the orFlags by 1 to check every bit to add the
                # corresponding flagVal to Account types if the bit is set.
            samAccountTypes >>= 1
            flagVal *= 2

        try:
            if self.__NTDS is not None:
                self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
                self.__cursor = self.__ESEDB.openTable('datatable')
        except Exception as e:
            LOG.error('Error opening the file')
            raise e

    def isIndexableRecord(self, record):
        if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.__ACCOUNT_TYPES:
            return True
        elif self.NAME_TO_INTERNAL['distinguishedName'] not in record:
            return False
        elif self.__fetchOU and record[self.NAME_TO_INTERNAL['distinguishedName']] is not None:
            distinguishedName = '%s' % record[self.NAME_TO_INTERNAL['distinguishedName']]
            if distinguishedName.startswith('OU'):
                return True
        return False
            
    def getNextRecord(self):
        record = self.__ESEDB.getNextRow(self.__cursor)
        if record is None:
            return None, False
        attributeMap = defaultdict(str)
        if self.NAME_TO_INTERNAL['sAMAccountType'] not in record:
            raise Exception('InvalidFile')
        try:
            if self.isIndexableRecord(record):
                if record[self.NAME_TO_INTERNAL['sAMAccountName']] is not None:
                    samAccountName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
                    attributeMap['samAccountName'] = samAccountName
                else:
                    if not self.__fetchOU:
                        return None, True
                if record[self.NAME_TO_INTERNAL['displayName']] is not None:
                    displayName = '%s' % record[self.NAME_TO_INTERNAL['displayName']]
                    attributeMap['name'] = displayName
                else:
                    return None, True
                if record[self.NAME_TO_INTERNAL['objectGUID']] is not None:
                    objectGuid = '%s' % record[self.NAME_TO_INTERNAL['objectGUID']]
                    attributeMap['guid'] = objectGuid
                else:
                    return None, True
                if record[self.NAME_TO_INTERNAL['distinguishedName']] is not None:
                    distinguishedName = '%s' % record[self.NAME_TO_INTERNAL['distinguishedName']]
                    attributeMap['dnName'] = distinguishedName
                else:
                    return None, True
                if distinguishedName.startswith('OU'):
                    objectType = 'ou'
                else:
                    objectType = self.SAM_ACCOUNT_TYPE_TO_OBJECT_CLASS[record[self.NAME_TO_INTERNAL['sAMAccountType']]]
                attributeMap['objectType'] = objectType
                return attributeMap, True
            else:
                return None, True
        except Exception as e:
            LOG.error(record)
            LOG.error(e)            
            raise Exception('Fetching of next record failed')

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()
