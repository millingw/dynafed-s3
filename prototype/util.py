# encryption / decryption code from stack overflow ...
# https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256

from Crypto.Cipher import AES
from Crypto import Random

import base64, hashlib, hmac

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


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def build_s3_error_response(code, message, resource, requestid):
    error_response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
        + "<Error>" \
        + "<Code>" + str(code) + "</Code>" \
        + "<Message>" + str(message) + "</Message>" \
        + "<Resource>" + str(resource) + "</Resource>" \
        + "<RequestId>" + str(requestid) + "</RequestId>" \
        + "</Error>"
    return error_response



def parse_query_parameters(param_string):

    if len(param_string) == 0:
        return ''

    split_params = param_string.split('&')

    # process the params into a dict for sorting
    param_dict = {}
    for s in split_params:
        s1 = s.split('=')
        if len(s1) == 1:
            param_dict[s1[0]] = ''
        else:
            param_dict[s1[0]] = s1[1]

    # sort by key, ie parameter name
    keylist = param_dict.keys()
    keylist.sort()

    # now turn the dict back into a string and return
    sorted_params = ''
    i=1
    for k in keylist:
        sorted_params = sorted_params + k + '=' + param_dict[k]
        if i < len(keylist):
            sorted_params = sorted_params + "&"
        i = i+1

    return sorted_params


def check_sig_version(authorisation):
        return authorisation.startswith("AWS4-HMAC-SHA256")


def validate_signature(user_key, x_amz_date, host,
                       processed_header, request_method, request_parameters, canonical_uri, headers):

    # get the alphabetically sorted query parameters
    sorted_params = parse_query_parameters(request_parameters)
    # replace any backslash characters in the params
    canonical_querystring = sorted_params.replace('/', '%2F')

   # Rebuild the canonical headers from the set of signed headers.

    signed_headers = processed_header['signed_headers']

   # somewhat annoyingly, the signed header names do not map exactly to the actual header properties
   # only way I can see round this is to iterate and compare everything as lowercase

    canonical_headers = ''
    for s in signed_headers.split(";"):
        for h in headers:
            if s.lower() == h[0].lower():
                canonical_headers = canonical_headers + s + ':' + h[1] + '\n'

   # Create payload hash (hash of the request body content). For GET
   # requests, the payload is an empty string ("").
   # TODO - check the actual content of POST and PUT

    payload_hash = hashlib.sha256('').hexdigest()

   # Combine elements to create create canonical request
    canonical_request = request_method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' \
      + signed_headers + '\n' + payload_hash

    #print "Canonical request:" , canonical_request


   # Rebuild the string to sign
    algorithm = processed_header['algorithm']
    credential_scope = processed_header['datestamp'] + '/' + processed_header['region'] + '/' + processed_header['service'] + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  x_amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()

    # regenerate the key for the signature checking
    signing_key = getSignatureKey(user_key, processed_header['datestamp'], processed_header['region'], processed_header['service'])

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    return signature == processed_header['signature']