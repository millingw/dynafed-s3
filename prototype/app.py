
from flask import Flask, redirect, url_for, request, Response, abort
from flask_restful import Resource, Api
import requests
import xml.etree.cElementTree as xml
from collections import namedtuple

from settings import BASE_DYNAFED_URL
from settings import USERNAME, USERPASS




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


@app.route('/', methods=['GET'])
def handle_list_buckets():
# list all the 'buckets' available to us and return them as a ListAllBuckets request
    results, status_code = list_directory_as_tuples(BASE_DYNAFED_URL)
    print results, status_code
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

    prefix = request.args.get('prefix')
    delimiter = request.args.get('delimiter')
    list_type = request.args.get('list-type')

    # if list_type not specified, assume we are looking for an object
    if list_type is None:

          # TODO: authenticate user from request url
          # TODO: encrypt token into url and sign url

          response = requests.head(BASE_DYNAFED_URL + entity)
          print response.status_code
          if response.status_code != 302:
		abort(response.status_code)
          dynafed_key_location = response.headers['location']
          return redirect(dynafed_key_location, 302)


    # AWS documentation says list-type must be '2'
    if list_type != "2":
	return Response("Invalid list-type argument, must be 2", 500)

    

    # naive version of code, does not handle prefix or delimiter
    results, status_code = list_directory_as_tuples(BASE_DYNAFED_URL + entity)
  
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
