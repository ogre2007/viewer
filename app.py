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
from flask_bootstrap import Bootstrap
import redis


logging.basicConfig()



UPLOAD_FOLDER = './files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
bootstrap = Bootstrap(app)
r = redis.StrictRedis('localhost', 6667, 2, charset='utf-8', decode_responses=True)



GHIDRA = {'id': 'ghidra', 'name': 'Дизассемблер', 'color': 'orange'}
BINWALK = {'id': 'binwalk', 'name': 'Поиск сигнатур', 'color': 'green'}
CAPA = {'id': 'capa', 'name': 'Поведенческий анализ', 'color': 'purple'}
TOOL_IDS = {'ghidra', 'binwalk', 'capa'}
TOOLS = [GHIDRA, BINWALK, CAPA] 
CONNS = {'ghidra': 'http://localhost:8080/ghidra/api'}

#####################################
#   INIT                            #
#####################################

def init_db():

    hashes = ['6ed58fe92eac477dc8c798c4e56152e2853468406d1d7da7a5250813413b0356', 
        'ca11a97eb88f411eb8924be79b2e0bfc1acebf98bf295b7926be5fb153ff611c']

    files = {hashes[0]:{
            'filename': 'malware.exe',
            'size': '50kb',
    },
        hashes[1]:{
            'filename': 'nicefile.exe',
            'size': '60kb',
    }
    }
    r.lpush('files', *hashes)


    with r.pipeline() as pipe:
        for f_id, f in files.items():
            pipe.hset(f_id, mapping = f)
        pipe.execute()

    
init_db()


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




#####################################
#   ANALYSIS                        #
#####################################

async def save_to_db(hash, blob, filename, size):
    with r.pipeline() as pipe:
        pipe.lpush('files', hash)
        pipe.hset(hash, 'filename', filename)
        pipe.hset(hash, 'blob', base64.b64encode(blob))
        pipe.hset(hash, 'size', f'{size/1024}KB')
        pipe.execute()

def load_from_db(h):
    return base64.b64decode(r.hget(h, 'blob'))


async def process_file(sha256, file, filename):
    blob = file
    await save_to_db(sha256, blob,filename, len(blob))

    await asyncio.gather(
        analyze_ghidra(sha256),
        analyze_binwalk(sha256),
        analyze_capa(sha256)
    )

async def analyze_ghidra(sha256):
    blob = load_from_db(sha256)
    bb = {'sample': io.BytesIO(blob)}

    resp = requests.post("%s/analyze_sample/" % CONNS['ghidra'], files=bb, timeout=300)
    if resp.status_code == 200:
        resp = requests.get("%s/get_functions_list/%s" % (CONNS['ghidra'], sha256), timeout=300)
        
        print("get_functions_list_detailed status_code:", resp.status_code)
        result = {}
        #data = json.loads(resp.text)['functions_list']
        result = json.dumps(resp.text)
        r.hset(sha256, key='code_analysis', value=result)
        return True
    print("something goes wrong with ghidra")
    return False

async def analyze_binwalk(sha256):
    result = ''
    r.hset(sha256, 'signatures', result)
    return False

async def analyze_capa(sha256):
    result =''
    r.hset(sha256, 'capabilities', result)
    return False

#####################################
#   API                             #
#####################################


@app.route('/download_file/<name>')
def download_file(name):
    return send_from_directory(app.config['UPLOAD_FOLDER'], name)

@app.route('/results/<hash>')
def results(hash):
    results = r.hgetall(hash)
    print(results)
    return render_template('results.html', hash=hash, tools=TOOLS, results = results)

@app.route('/results/<hash>/<tool>')
def results_get(hash, tool):
    return (r.hget(hash, tool), 200)


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
    logging.warning(files)
    return render_template('index.html', title='Main page', files=files)


if __name__ == '__main__':
    
    app.run(debug=True)
