#!/usr/bin/python
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from Crypto import Random
import base64

# Simple script that prints its arguments and then decides if the user has
# to be authorized
# usage:
# ugrauth_example.py <clientname> <remoteaddr> <fqan1> .. <fqanN>
#
# Return value means:
# 0 --> access is GRANTED
# nonzero --> access is DENIED
#

import sys

# A class that one day may implement an authorization list loaded
# from a file during the initialization of the module.
# If this list is written only during initialization, and used as a read-only thing
# no synchronization primitives (e.g. semaphores) are needed, and the performance will be maximized

unpad = lambda s : s[:-ord(s[len(s)-1:])]
def decrypt(enc, key ):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( enc[16:] ))


class _Authlist(object):
    def __init__(self):
        print "I claim I am loading an authorization list from a file, maybe one day I will :-)"

# Initialize a global instance of the authlist class, to be used inside the isallowed() function
myauthlist = _Authlist()



# The main function that has to be invoked from ugr to determine if a request
# has to be performed or not
def isallowed(clientname="unknown", remoteaddr="nowhere", resource="none", mode="0", fqans=None, keys=None):
    

    #print "XXXXXXXXX Start XXXXXXXXXXXXX"
    #print "clientname", clientname
    #print "remote address", remoteaddr
    #print "fqans", fqans
    #print "keys", keys
    #print "mode", mode
    #print "resource", resource
    #print "type", type(keys)


    token = None
    for k in keys:
      if k[0] == "auth_token":
        token = k[1]
        break 
    
    # no access if token not found     
    if token is None:
        return 1

    # attempt to decrypt the token;
    # failure means no access
    try:
       token = decrypt(token, *****)
    except Exception, e:
       # TODO: log the error?
       return 1


    # process the token into constituent parts
    token_strings = token.split("/")

    if len(token_strings) != 3:
       return 1

    user_id = token_strings[0]
    timestamp = token_strings[1]
    roles = token_strings[2]

    # TODO - process timestamp to check valid


    # TODO - make some decisions based on roles
    # for the moment just check the operation role
    # matches one of the ones passed in the token
    if mode in roles: 
       return 0
    else:
       return 1

    
    # Read/list modes are always open
    #if (mode == 'r') or (mode == 'l'):
    #  return 0


    # deny to anonymous user for any write mode
    #if (clientname == 'nobody'):
    #  return 1

    # allow writing to anyone else who is not nobody
    #return 0


#------------------------------
if __name__ == "__main__":
    r = isallowed(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    sys.exit(r)