
from flask import Flask, redirect, url_for, request
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

File = namedtuple('File', ['name', 'size', 'mtime', 'ctime', 'contenttype'])


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
    )


@app.route('/s3/<path:filename>', methods=['GET'])
def retrieve_file(filename):
    return redirect(BASE_DYNAFED_URL + filename, 302)


@app.route('/list/<path:directory>', methods=['GET'])
def list_directory(directory):
  
    headers = {'Depth': '1'}
    r = requests.request('PROPFIND', BASE_DYNAFED_URL + directory, headers=headers, auth=(USERNAME, USERPASS) )
    
    tree = xml.fromstring(r.content)
    results = [elem2file(elem) for elem in tree.findall('{DAV:}response')]

    #TODO - convert to S3 ListBucketResult format

    str_list = []
    for f in results:
        str_list.append(str(f))
    out_str = ''.join(str_list)
    return out_str



if __name__ == '__main__':
    app.config.from_object('settings')
    app.run(debug=True)
