import os
import logging
import hashlib
import asyncio
import io
import base64
import json

import requests
from flask import Flask, flash, request, redirect, url_for, send_from_directory, render_template
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import HTTPException
import redis




UPLOAD_FOLDER = './files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
r = redis.StrictRedis('localhost', 6667, 0, charset='utf-8', decode_responses=True)

GHIDRA = 'ghidra'
BINWALK = 'binwalk'
CAPA = 'capa'

ANALYZERS = {'ghidra', 'binwalk', 'capa'}
ADDRESSES = {'ghidra': 'localhost:8080/ghidra/api', 'binwalk':'localhost:8081', 'capa': 'localhost:8082'}
UPLOAD_URLS = {'ghidra': 'upload', 'binwalk': 'upload', 'capa': 'upload' }
ANALYZE_URLS = {'ghidra': 'analyze', 'binwalk': 'analyze', 'capa': 'analyze' }

RESULT_SERVICE_MAPPING = {'code_analysis': GHIDRA, 'signatures': BINWALK, 'capabilities': CAPA}

#####################################
#   INIT                            #
#####################################

class Analyzer(object):
    def __init__(self, name, address, upload_url, analyze_url):
        self.name = name
        self.address = address
        self.upload_url = upload_url
        self.analyze_url = analyze_url

    async def upload(self, blob, sha256 = None):
        if not sha256:
            sha256 = sha256_hash(blob)
        resp = requests.post(f'http://{self.address}/{self.upload_url}' , 
            files={'file': io.BytesIO(blob)},
            params={'id': sha256})
        return resp

    async def analyze(self, sha256):
        resp = requests.get(f'http://{self.address}/{self.analyze_url}' , 
            params={'id': sha256},
            timeout=300)
        return resp
    
    def ping(self):
        pass


class GhidraAnalyzer(Analyzer):
    async def analyze(self, sha256):
        resp = requests.get(f'http://{self.address}/analyze_sample' , 
            params={'id': sha256},
            timeout=300)
        if resp.status_code == 200:
            resp = await Analyzer.analyze(self, sha256)
        else:
            print(f'something wrong with ghidra initial analysis:{resp.text}')
        return resp




Analyzers_list = [GhidraAnalyzer(GHIDRA, ADDRESSES[GHIDRA],
                                 UPLOAD_URLS[GHIDRA], ANALYZE_URLS[GHIDRA]),
    Analyzer(BINWALK, ADDRESSES[BINWALK],
                                 UPLOAD_URLS[BINWALK], ANALYZE_URLS[BINWALK]),
        Analyzer(CAPA, ADDRESSES[CAPA],
                                 UPLOAD_URLS[CAPA], ANALYZE_URLS[CAPA])
]
#####################################
#   UTILS                           #
#####################################

def sha256_hash(blob):
    """
    Compute the sha256 of the stream in input
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(blob)
    return sha256_hash.hexdigest()


def save_to_db(h, filename, size):
    r.lpush('files', h)
    r.hset(h, 'name', filename)
    r.hset(h, 'size', '%fMB' % (size/(1024*1024)))
    return True

def load_from_db(h):
    return base64.b64decode(r.hget(h, 'blob'))

#####################################
#   API                             #
#####################################

async def process_file(sha256, file, filename):
    blob = file
    save_to_db(sha256, filename, len(blob))
    await asyncio.gather(*[analyzer.upload(blob, sha256) for analyzer in Analyzers_list])


@app.route('/results/<hash>')
def results(hash):
    if r.exists('files', hash):
        name = r.hget(hash, 'name')
        return render_template('results.html', hash=hash, name=name)
    else:
        return render_template('404.html')

@app.route('/results/<h>/<result_type>')
async def results_get(h, result_type):
    try:
        svc_name = RESULT_SERVICE_MAPPING[result_type]
        for an in Analyzers_list:
            if an.name == svc_name:
                resp = await an.analyze(h)
                print(resp.status_code, resp.text)
                return (resp.text, resp.status_code)
        else:
            raise BadRequest(f"no such analyzer: {svc_name}")
    except KeyError as e:
        return BadRequest("no such result")
    return ('Not found', 404)


@app.route('/upload_file', methods=['POST'])
async def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            blob = file.read()
            h = sha256_hash(blob)
            logging.warning(f'hash for {file.filename} is {h}')
            await process_file(h, blob, file.filename)
            
            
            return redirect('/index.html')



@app.route('/index.html')
@app.route('/')
def index():

    hashes = r.lrange('files', 0, -1)
    files = dict()
    for h in hashes:
        files[h] = r.hgetall(h)
    #logging.warning(files)
    return render_template('index.html', title='Main page', files=files)


if __name__ == '__main__':
    
    app.run(debug=True)
