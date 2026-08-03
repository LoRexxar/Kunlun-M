import os, subprocess
from flask import request

def run_cmd():
    cmd = request.GET.get('cmd')
    os.system(cmd)
    subprocess.call(cmd, shell=True)
