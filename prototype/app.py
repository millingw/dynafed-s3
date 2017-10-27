from flask import Flask, redirect, url_for, request, Response, abort
from flask_restful import Resource, Api
import requests
import xml.etree.cElementTree as xml
from collections import namedtuple
import sys, os, base64, datetime, hashlib, hmac
from Crypto.Cipher import AES
from Crypto import Random

from datetime import datetime

from settings import BASE_DYNAFED_URL
from settings import ID_TO_KEY, ID_TO_ROLES, AUTH_TOKEN_NAME, ENCRYPTION_KEY



app = Flask(__name__)
api = Api(app)


# encryption / decryption code from stack overflow ...
# https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256

BS = 32
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = key

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


# WebDAV extraction code based on easywebdav ls method
# https://github.com/amnong/easywebdav

File = namedtuple('File', ['name', 'size', 'mtime', 'ctime', 'contenttype', 'displayname', 'etag', 'iscollection'])


def prop(elem, name, default=None):
    child = elem.find('.//{DAV:}' + name)
    return default if child is None else child.text


def elem2file(elem):
    return File(
        prop(elem, 'href'),
        int(prop(elem, 'getcontentlength', 0)),
        prop(elem, 'getlastmodified', ''),
        prop(elem, 'creationdate', ''),
        prop(elem, 'getcontenttype', ''),
        prop(elem, 'displayname', ''),
        prop(elem, 'getetag', ''),
        int(prop(elem, 'iscollection', 0)),
    )


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def list_directory_as_tuples(path):

   # dynafed will only let us descend one directory level at a time,
   # 'infinte' depth is not supported
   headers = {'Depth': '1'}

   r = requests.request('PROPFIND', path, headers=headers )
   if r.status_code != 207:
        return None, r.status_code

   tree = xml.fromstring(r.content)
   results = [elem2file(elem) for elem in tree.findall('{DAV:}response')]

   return results, r.status_code




# extract the authorization information
# and return all relevant information as a dict
def process_authorization_header(authorization):

    auth_split = authorization.split(',')
    algorithm = None
    credential = None
    requestSignedHeaders = None
    signature = None

    # first entry should be the algorithm followed by a space, then the credential
    if len(auth_split) == 0:
        raise

    s1 = auth_split[0].split(' ')
    algorithm = s1[0]
    credential = s1[1]
    credential_split = credential.split('/')
    identity = None
    date = None
    region = None
    service = None


    if len(credential_split) > 0:
          identity = credential_split[0].split('=')[1]
          date = credential_split[1]
          region = credential_split[2]
          service = credential_split[3]

    for s in auth_split:
          if 'SignedHeaders' in s:
                split1 = s.split('=')
                requestSignedHeaders = split1[1]
          elif 'Signature' in s:
                split1 = s.split('=')
                signature = split1[1]

    result = {}
    result["algorithm"] = algorithm
    result["credential"] = credential
    result["signed_headers"] = requestSignedHeaders
    result["signature"] = signature
    result["identity"] = identity
    result["datestamp"] = date
    result["region"] = region
    result["service"] = service

    return result


# get our minimum set of headers from the request;
# others may be needed when we get to checking the signature,
# but we can't even get that far if our minimum set isn't present
# minimum set here is Authorization, X-Amz-Date and host
def get_required_headers(request):

    authorization = None
    x_amz_date = None
    host = None


    try:
       authorization = request.headers['Authorization']
    except:
       raise Exception("Authorization header not found")

    try:
       x_amz_date = request.headers['X-Amz-Date']
    except:
       raise Exception("x-amz-date header not found")

    try:
       host = request.headers['host']
    except:
       raise Exception("host header not found")

    return authorization, x_amz_date, host


def validate_signature(user_key, x_amz_date, host, processed_header, request_method, request_parameters):
   # regenerate the key for the signature checking

    sig_key = getSignatureKey(user_key, processed_header["datestamp"], processed_header["region"], processed_header["service"])


    canonical_uri = '/'

    # Create the canonical query string.

    canonical_querystring = request_parameters
    

   # Rebuild the canonical headers from the set of signed headers.

    signed_headers = processed_header['signed_headers']

   # somewhat annoyingly, the signed header names do not map exactly to the actual header properties
   # only way I can see round this is to iterate and compare everything as lowercase

    canonical_headers = ''
    for s in signed_headers.split(";"):
        for h in request.headers:
            if s.lower() == h[0].lower():
                canonical_headers = canonical_headers + s + ':' + h[1] + '\n'

   # Create payload hash (hash of the request body content). For GET
   # requests, the payload is an empty string ("").
   # TODO - check the actual content of POST and PUT

    payload_hash = hashlib.sha256('').hexdigest()

   # Combine elements to create create canonical request
    canonical_request = request_method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' \
      + signed_headers + '\n' + payload_hash


   # Rebuild the string to sign
    algorithm = processed_header['algorithm']
    credential_scope = processed_header['datestamp'] + '/' + processed_header['region'] + '/' + processed_header['service'] + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  x_amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()

    signing_key = getSignatureKey(user_key, processed_header['datestamp'], processed_header['region'], processed_header['service'])

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    return signature == processed_header['signature']



@app.route('/', methods=['GET'])
def handle_list_all_my_buckets():
# list all the 'buckets' available to us and return them as a ListAllBuckets request

    authorization = None
    x_amz_date = None

    try:
       authorization, x_amz_date, host = get_required_headers(request)
    except Exception, e:
       return str(e), 400

    processed_header = None

    try:
       processed_header = process_authorization_header(authorization)
    except:
       return "Could not process authorization header", 500

    # should now have the user's identity, look them up in our map
    identity = processed_header.get("identity")
    user_key = ID_TO_KEY.get(identity)
    if user_key is None:
       return "No key found for identity", 403

    if validate_signature(user_key, x_amz_date, host, processed_header, request.method, request.query_string) == False:
        return "signature invalid", 500


    # signature seems valid, check timestamp hasn't expired
    # x-amz-date should be in form YYYYMMDDT
    supplied_timestamp = datetime.strptime(x_amz_date, "%Y%m%dT%H%M%SZ")
    delta = datetime.utcnow() - supplied_timestamp

    # TODO how long do we allow before expiring a timestamp?

    # get the user's roles
    user_roles = ID_TO_ROLES.get(identity)
    if user_roles is None:
        return "No roles found", 403

    # build the security token to be encrypted and sent in the query string
    raw_token = identity + "/" + x_amz_date + "/" + user_roles

    # encrypt the token
    ciph = AESCipher(ENCRYPTION_KEY)
    encrypted_token = ciph.encrypt(raw_token)



    results, status_code = list_directory_as_tuples(BASE_DYNAFED_URL + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token)

    response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    response = response + "<ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
    response = response + "<Buckets>"
    for r in results:
	response = response + "<Bucket>"
        response = response + "<Name>" + r.displayname + "</Name>"
        response = response + "<CreationDate>" + r.mtime + "</CreationDate>"
        response = response + "</Bucket>"
    response = response + "</Buckets>"
    response = response + "</ListAllMyBucketsResult>"
    return Response(response, mimetype='text/xml')


@app.route('/<path:entity>', methods=['GET'])
def handle_s3_request(entity):


    authorization = None
    x_amz_date = None

    try:
       authorization, x_amz_date, host = get_required_headers(request)
    except Exception, e:
       return str(e), 400

    processed_header = None

    try:
       processed_header = process_authorization_header(authorization)
    except:
       return "Could not process authorization header", 500


    # should now have the user's identity, look them up in our map
    identity = processed_header.get("identity")
    user_key = ID_TO_KEY.get(identity)
    if user_key is None:
       return "No key found for identity", 403

    if validate_signature(user_key, x_amz_date, host, processed_header, request.method, request.query_string) == False:
        return "signature invalid", 500

     # signature seems valid, check timestamp hasn't expired
    # x-amz-date should be in form YYYYMMDDT
    supplied_timestamp = datetime.strptime(x_amz_date, "%Y%m%dT%H%M%SZ")
    delta = datetime.utcnow() - supplied_timestamp

    # TODO how long do we allow before expiring a timestamp?

    # get the user's roles
    user_roles = ID_TO_ROLES.get(identity)
    if user_roles is None:
        return "No roles found", 403


    # build the security token to be encrypted and sent in the query string
    raw_token = identity + "/" + x_amz_date + "/" + user_roles

    # encrypt the token

    ciph = AESCipher(ENCRYPTION_KEY)
    encrypted_token = ciph.encrypt(raw_token)


    list_type = None
    try:
        list_type = request.args['list_type']
    except:
        list_type = None


    # if list_type not specified, assume we are looking for an object
    if list_type is None:
          return redirect(BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token, 302)


    # AWS documentation says list-type must be '2'
    if list_type != "2":
	return Response("Invalid list-type argument, must be 2", 500)

    # note - code does not use these yet;
    # TODO use them ...
    prefix = request.args.get('prefix')
    delimiter = request.args.get('delimiter')
    list_type = request.args.get('list-type')

    # naive version of code, does not handle prefix or delimiter
    results, status_code = list_directory_as_tuples(BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token)

    if status_code != 207:
	return Response("Error calling remote system", status_code)


    response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    response = response + "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
    response = response + "<Name>" + entity + "</Name>"
    response = response + "<Prefix/>"
    response = response + "<KeyCount>" + str(len(results)) + "</KeyCount>"
    for r in results:
	response = response + "<Contents>"
        response = response + "<Key>" + r.displayname + "</Key>"
        response = response + "<LastModified>" + r.mtime + "</LastModified>"
        response = response + "<Etag>" + r.etag + "</Etag>"
        response = response + "<Size>" + str(r.size) + "</Size>"
        response = response + "<StorageClass>STANDARD</StorageClass>"
        response = response + "</Contents>"
    response = response + "</ListBucketResult>"
    return Response(response, mimetype='text/xml')


if __name__ == '__main__':
    app.config.from_object('settings')
    app.run(debug=True)



