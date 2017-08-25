# AWS Version 4 signing example

# EC2 API (DescribeRegions)

# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
# This version makes a GET request and passes the signature
# in the Authorization header.
import sys, os, base64, datetime, hashlib, hmac 
import requests # pip install requests

import string
import re

from time import time, clock

# ************* REQUEST VALUES *************
method = 'GET'
service = 'ec2'
host = 'ec2.amazonaws.com' # Can't have a port number here, otherwise error 401 Auth Failure is returned
region = 'us-east-1'
endpoint = 'https://ec2.amazonaws.com'
request_parameters = 'Action=DescribeRegions&Version=2013-10-15'

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning
    
    
    
def getSignedHeaderNames(authzHeader):
	
    sigh = None
        
    match = re.search(r'SignedHeaders=(([a-z;,-])+)' , authzHeader)
    
    if (match.group(1)) is not None:
    	sigh = match.group(1)
    	
    return sigh
    
    
def getSignedHeaderNamesArr(signedHeaderNames):

    signedHeaders = re.split('[;]', signedHeaderNames)
#    del signedHeaders[len(signedHeaders)-1]
        
    return signedHeaders
    
def tupleFrom(inStr, sep):
	
	return tuple(item for item in inStr.split(sep))
    
#def getCanonicalHeaders(req):
#	req_headers = req.headers
#	req_headers['host'] = 'host'
#	
#    req_headers['host'] = netloc # 'host' is part of the URL, not in HTTP headers?
#
#    res_canonical_headers = ''
#
#    for signedHeader in signedHeaders:
#    
#	    res_canonical_headers = res_canonical_headers + signedHeader + ':' + req_headers[signedHeader] + '\n'	
#    return authzHeader[pos:commapos]

# Read AWS access key from env. variables or configuration file. Best practice is NOT
# to embed credentials in code.
access_key = os.environ.get('AWS_ACCESS_KEY_ID')
secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
if access_key is None or secret_key is None:
    print 'No access key is available.'
    sys.exit()

# Create a date for headers and the credential string
t = datetime.datetime.utcnow()
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

start = time() # clock()

# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# Step 1 is to define the verb (GET, POST, etc.)--already done.

# Step 2: Create canonical URI--the part of the URI from domain to query 
# string (use '/' if no path)
canonical_uri = '/' 

# Step 3: Create the canonical query string. In this example (a GET request),
# request parameters are in the query string. Query string values must
# be URL-encoded (space=%20). The parameters must be sorted by name.
# For this example, the query string is pre-formatted in the request_parameters variable.
canonical_querystring = request_parameters

# Step 4: Create the canonical headers and signed headers. Header names
# must be trimmed and lowercase, and sorted in code point order from
# low to high. Note that there is a trailing \n.
canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'



# Step 5: Create the list of signed headers. This lists the headers
# in the canonical_headers list, delimited with ";" and in alpha order.
# Note: The request can include any headers; canonical_headers and
# signed_headers lists those that you want to be included in the 
# hash of the request. "Host" and "x-amz-date" are always required.
signed_headers = 'host;x-amz-date'

# Step 6: Create payload hash (hash of the request body content). For GET
# requests, the payload is an empty string ("").
payload_hash = hashlib.sha256('').hexdigest()

# Step 7: Combine elements to create create canonical request
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

task1 = time() - start

# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
algorithm = 'AWS4-HMAC-SHA256'
credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()

print 'String to sign = ' + string_to_sign
task2 = time()  - task1

# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
signing_key = getSignatureKey(secret_key, datestamp, region, service)

# Sign the string_to_sign using the signing_key
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

task3 = time() - task2

# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# The signing information can be either in a query string value or in 
# a header named Authorization. This code shows how to use a header.
# Create authorization header and add to request headers
authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

# The request can include any headers, but MUST include "host", "x-amz-date", 
# and (for this scenario) "Authorization". "host" and "x-amz-date" must
# be included in the canonical_headers and signed_headers, as noted
# earlier. Order here is not significant.
# Python note: The 'host' header is added automatically by the Python 'requests' library.
headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}

task4 = time() - task3

print 'Task 1 took ' + str(task1)
print 'Task 2 took ' + str(task2)
print 'Task 3 took ' + str(task3)
print 'Task 4 took ' + str(task4)

print "Authorization_header: "
print authorization_header

print 
# ************* SEND THE REQUEST *************
request_url = endpoint + '?' + canonical_querystring

print '\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++'
print 'Request URL = ' + request_url
r = requests.get(request_url, headers=headers)


print "Request headers: "
print "Headers:"
print r.request.headers
print "Request URI:" + r.request.url

req_headers = r.request.headers
req_url = r.request.url



print '\nRESPONSE++++++++++++++++++++++++++++++++++++'
print 'Response code: %d\n' % r.status_code
#print r.text

resreq = r.request

print "Request from response = " 
print resreq

req_url = resreq.url
print "Requset URL = " + req_url

req_headers = resreq.headers


req_authz = req_headers['Authorization']

print 'REQ_AUTHZ = \n\n' + req_authz + '\n\n'

#print 'req_headers = \n' + req_headers + '\n'


method = 'GET'

#req_authz = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"


(req_algorithm, req_cred, headers, req_signature) = tupleFrom(req_authz, ' ')

req_signature = req_signature[len('Signature='):]

req_cred = req_cred[:-1]

print 'alg = ' + req_algorithm
print 'cred = ' + req_cred
print 'headers = ' + headers
print 'signature = ' + signature



req_cred = req_cred[len('Credential='):]

(req_access_key, req_datestamp, req_region, req_service, req_aws_request) = tupleFrom(req_cred, '/') 

req_aws_request = req_aws_request[:-1]
 

from urlparse import urlparse

(scheme, netloc, req_canonical_uri, params, req_canonical_querystring, fragment) = urlparse(req_url)

#print "Netloc = " + netloc + ", path = " + path + ", params = " + params + ", query = " + query + ", fragment = " + fragment

req_amzdate = req_headers['x-amz-date']  # Default is for this as a header, not in the querystring

req_payload_hash = hashlib.sha256('').hexdigest() # GET request does not have a 'payload' (no BODY)

assert payload_hash == req_payload_hash

req_method = 'GET'


req_signed_headers = getSignedHeaderNames(req_authz)[:-1] # We return an array


req_headers['host'] = netloc # 'host' is part of the URL, not in HTTP headers?


sigh = getSignedHeaderNamesArr(req_signed_headers)



 
req_canonical_headers = ''

#print 'Names of signed headers = \n'
#print sigh

for signedHeader in sigh:
	    
	req_canonical_headers = req_canonical_headers + signedHeader + ':' + req_headers[signedHeader] + '\n' 

print 'canonical_headers = \n'
print canonical_headers


print 'req_canonical_headers = \n'

print req_canonical_headers

print '\n'

assert canonical_headers == req_canonical_headers
	
req_canonical_request = req_method + '\n' + req_canonical_uri + '\n' + req_canonical_querystring + '\n' + req_canonical_headers + '\n' + req_signed_headers + '\n' + req_payload_hash


req_credential_scope = req_datestamp + '/' + req_region + '/' + req_service + '/' + 'aws4_request'


req_string_to_sign = req_algorithm + '\n' + req_amzdate + '\n' + req_credential_scope + '\n' + hashlib.sha256(req_canonical_request).hexdigest()


#print 'Signs to sign:\n'
#print string_to_sign
#print '\n'
#print req_string_to_sign
#print '\n\n'

req_signing_key = getSignatureKey(secret_key, req_datestamp, req_region, req_service)


req_signature = hmac.new(req_signing_key, (req_string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()



assert signature == req_signature

req_authorization_header = req_algorithm + ' ' + 'Credential=' + access_key + '/' + req_credential_scope + ', ' +  'SignedHeaders=' + req_signed_headers + ', ' + 'Signature=' +  req_signature

req_headers = {'x-amz-date':req_amzdate, 'Authorization':req_authorization_header}


