from flask import Flask, redirect, request, Response
from flask_restful import Api
import requests
import xml.etree.cElementTree as xml
from collections import namedtuple


from util import AESCipher
from util import validate_signature
from util import build_s3_error_response
from util import check_sig_version

from datetime import datetime

from settings import BASE_DYNAFED_URL
from settings import ID_TO_KEY, ID_TO_ROLES, AUTH_TOKEN_NAME, ENCRYPTION_KEY

# buffer size for file streaming (in bytes)
STREAMING_CHUNK_SIZE = 1024


app = Flask(__name__)
api = Api(app)


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


# lists the properties of a path or object in DynaFed's WebDAV interface
# (there may be better ways to do this ...)
def list_directory_as_tuples(path):

   # dynafed will only let us descend one directory level at a time,
   # 'infinte' depth is not supported
   headers = {'Depth': '1'}

   r = requests.request('PROPFIND', path, headers=headers)
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



@app.route('/', methods=['GET'])
def handle_list_all_my_buckets():
# list all the 'buckets' available to us and return them as a ListAllBuckets request

    authorization = None
    x_amz_date = None

    try:
       authorization, x_amz_date, host = get_required_headers(request)
    except Exception, e:
       return str(e), 400

    if check_sig_version(authorization) == False:
        return build_s3_error_response("InvalidRequest",
                "Please use AWS4-HMAC-SHA256","", 0), 400

    processed_header = None

    try:
       processed_header = process_authorization_header(authorization)
    except Exception, e:
       return "Could not process authorization header", 400


    # should now have the user's identity, look them up in our map
    identity = processed_header.get("identity")
    user_key = ID_TO_KEY.get(identity)
    if user_key is None:
       return "No key found for identity", 403

    canonical_uri = "/"

    if validate_signature(user_key, x_amz_date, host, processed_header,
                          request.method, request.query_string, canonical_uri, request.headers) == False:
        return "signature invalid", 400


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




# decide if the user wants to get an object or do a listing
# if they want an object, get the object url from dynafed and stream the data
# otherwise call dynafed's webdav interface and return a ListBucket result
@app.route('/<path:entity>', methods=['GET'])
def handle_s3_request(entity):


    try:
       authorization, x_amz_date, host = get_required_headers(request)
    except Exception, e:
       return build_s3_error_response("MissingSecurityHeader",
                "mandatory header missing or could not be processed", entity, 0), 400

    if check_sig_version(authorization) == False:
        return build_s3_error_response("InvalidRequest",
                "Please use AWS4-HMAC-SHA256","", 0), 400
    processed_header = None

    try:
       processed_header = process_authorization_header(authorization)
    except Exception, e:
       return "Could not process authorization header", 400


    # should now have the user's identity, look them up in our map
    identity = processed_header.get("identity")
    user_key = ID_TO_KEY.get(identity)
    if user_key is None:
        return build_s3_error_response("InvalidAccessKeyId",
                "Identity not recognised",identity, 0), 403

    prefix = request.args.get('prefix')
    delimiter = request.args.get('delimiter')

    canonical_uri = "/" + entity

    if validate_signature(user_key, x_amz_date, host, processed_header,
                          request.method, request.query_string, canonical_uri, request.headers) == False:
         return build_s3_error_response("SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided.", entity, 0), 403

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

    # delimiter and prefix are none, assuming we are getting an object
    if ( delimiter is None and prefix is None):

           # build the federated url of the object as accesible via DynaFed
           target_url = BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token

	   # get the location, NOT the contents
           response = requests.head(BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token)
           if response.status_code == 404:
                return build_s3_error_response("NoSuchKey","Key not found", entity, 0), 404
           elif response.status_code == 403:
                return build_s3_error_response("AccessDenied","Access Denied", entity, 0), 403
           elif response.status_code != 200:
                return build_s3_error_response("InternalError","Something bad happened", entity, 0), 500
           else:
		# stream data back to the client, don't read the whole object into memory
                r = requests.get(target_url, stream=True)
                content_type = r.headers['Content-Type']
                content_length = r.headers['Content-Length']
                def downloader():
                        yield ''
                        for chunk in r.iter_content(STREAMING_CHUNK_SIZE):
                                yield chunk
                return Response(downloader(), mimetype=content_type, headers={ "content-length": content_length})

    # if we got here we're doing a listing
    bucketname = ""
    # s3cmd appears to add a backslash char to the bucketname,
    # whereas aws cli does not
    if entity.endswith('/'):
        bucketname = entity[:-1]
    else:
        bucketname = entity

    path = BASE_DYNAFED_URL + bucketname

    if prefix and prefix.strip():
        path = path + "/" + prefix
    path = path + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token

    results, status_code = list_directory_as_tuples(path)

    if status_code != 207:
	return Response("Error calling remote system", status_code)

    # munge the listing into a formatted S3 response
    # TODO - use more efficient string handling in what follows

    response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    response = response + "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
    response = response + "<Name>" + bucketname + "</Name>"
    if prefix and prefix.strip():
        response = response + "<Prefix>" + prefix + "</Prefix>"
    else:
        response = response + "<Prefix/>"

    if delimiter is not None:
        response = response + "<Delimiter>" + delimiter + "</Delimiter>"




    # dynafed returns names as /myfed/<bucketname>/key
    # so we need to purge some stuff from the front of the name
    purgestring = "/myfed/" + bucketname + "/"

    contents = ""
    common_prefixes = ""
    keycount = 0

    compare_dirname = ""
    if prefix and prefix.strip():
        compare_dirname = prefix + "/"

    
    for r in results:

        name = r.name.replace(purgestring, "", 1)

        if r.iscollection == 0:
              contents = contents + "<Contents>"
              contents = contents + "<Key>" +  name + "</Key>"
              contents = contents + "<LastModified>" + r.mtime + "</LastModified>"
              contents = contents + "<ETag>&quot;" + r.etag + "&quot;</ETag>"
              contents = contents + "<Size>" + str(r.size) + "</Size>"
              contents = contents + "<StorageClass>STANDARD</StorageClass>"
              contents = contents + "</Contents>"
              keycount = keycount + 1
        else:
            # the propfind query can do some strange things,
            # including returning the name of the directory we actually want to search.
            # looks weird, so we ignore it if it's supplied
            if len(name) > 0:
                  if name != compare_dirname:
                        common_prefixes = common_prefixes + "<CommonPrefixes><Prefix>"
                        common_prefixes = common_prefixes + name + "</Prefix></CommonPrefixes>"
                        keycount = keycount + 1

    response = response + "<KeyCount>" + str(keycount) + "</KeyCount>"
    if len(contents) > 0:
        response = response + contents
    if len(common_prefixes) > 0:
        response = response + common_prefixes

    response = response + "</ListBucketResult>"
    
    return Response(response, mimetype='text/xml')
           

# previous version which tries to issue a redirect to the backend;
# found not to work due to S3 307 redirect protocol.
# use handle_s3_request instead!
#def handle_s3_request_redirect(entity):
#
#    authorization = None
#    x_amz_date = None
#
#    try:
#       authorization, x_amz_date, host = get_required_headers(request)
#    except Exception, e:
#       return build_s3_error_response("MissingSecurityHeader",
#                "mandatory header missing or could not be processed", entity, 0), 400
#
#    if check_sig_version(authorization) == False:
#        return build_s3_error_response("InvalidRequest",
#                "Please use AWS4-HMAC-SHA256","", 0), 400
#    processed_header = None
#
#    try:
#       processed_header = process_authorization_header(authorization)
#    except Exception, e:
#       return "Could not process authorization header", 400
#
#
#    # should now have the user's identity, look them up in our map
#    identity = processed_header.get("identity")
#    user_key = ID_TO_KEY.get(identity)
#    if user_key is None:
#        return build_s3_error_response("InvalidAccessKeyId",
#                "Identity not recognised",identity, 0), 403
#
#    prefix = request.args.get('prefix')
#    delimiter = request.args.get('delimiter')
#
#    canonical_uri = "/" + entity
#
#    if validate_signature(user_key, x_amz_date, host, processed_header,
#                          request.method, request.query_string, canonical_uri, request.headers) == False:
#         return build_s3_error_response("SignatureDoesNotMatch",
#                "The request signature we calculated does not match the signature you provided.", entity, 0), 403
#
#     # signature seems valid, check timestamp hasn't expired
#    # x-amz-date should be in form YYYYMMDDT
#    supplied_timestamp = datetime.strptime(x_amz_date, "%Y%m%dT%H%M%SZ")
#    delta = datetime.utcnow() - supplied_timestamp
#
#    # TODO how long do we allow before expiring a timestamp?
#
#    # get the user's roles
#    user_roles = ID_TO_ROLES.get(identity)
#    if user_roles is None:
#        return "No roles found", 403
#
#
#    # build the security token to be encrypted and sent in the query string
#    raw_token = identity + "/" + x_amz_date + "/" + user_roles
#
#    # encrypt the token
#
#    ciph = AESCipher(ENCRYPTION_KEY)
#    encrypted_token = ciph.encrypt(raw_token)
#
#    # delimiter and prefix are none, assuming we are getting an object
#    if ( delimiter is None and prefix is None):
#
#          # check the object exists by issuing a HEAD request and checking the reponse
#
#          response = requests.head(BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token)
#          if response.status_code == 404:
#              return build_s3_error_response("NoSuchKey","Key not found", entity, 0), 404
#          elif response.status_code == 403:
#              return build_s3_error_response("AccessDenied","Access Denied", entity, 0), 403
#          elif response.status_code != 200:
#              return build_s3_error_response("InternalError","Something bad happened", entity, 0), 500
#          else:
#              return redirect(BASE_DYNAFED_URL + entity + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token, 302)
#
#    # naive version of code, does not handle prefix or delimiter
#    path = BASE_DYNAFED_URL + entity
#    if prefix is not None:
#        path = path + prefix
#    path = path + "?" + AUTH_TOKEN_NAME + "=" + encrypted_token
#    results, status_code = list_directory_as_tuples(path)
#
#    if status_code != 207:
#	return Response("Error calling remote system", status_code)
#
#
#    response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
#    response = response + "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
#    response = response + "<Name>" + entity + "</Name>"
#    if prefix is None:
#        response = response + "<Prefix/>"
#    else:
#        response = response + "<Prefix>" + prefix + "</Prefix>"
#    response = response + "<KeyCount>" + str(len(results)) + "</KeyCount>"
#
#    # dynafed returns names as /myfed/<entity>/key
#    # so we need to purge some stuff from the front of the name
#
#    purgestring = "/myfed/" + entity
#
#
#    for r in results:
#        response = response + "<Contents>"
#        response = response + "<Key>" +  r.name.replace(purgestring, "", 1) + "</Key>"
#        response = response + "<LastModified>" + r.mtime + "</LastModified>"
#        response = response + "<ETag>&quot;" + r.etag + "&quot;</ETag>"
#        response = response + "<Size>" + str(r.size) + "</Size>"
#        response = response + "<StorageClass>STANDARD</StorageClass>"
#        response = response + "</Contents>"
#
#
#    response = response + "</ListBucketResult>"
#
#
#    return Response(response, mimetype='text/xml')

	
	
	
	
if __name__ == '__main__':
    app.config.from_object('settings')
    app.run(debug=True)



