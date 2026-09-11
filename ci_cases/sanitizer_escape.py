import os
cmd = request.GET.get('cmd')
# This is a REAL vuln — shlex.quote is applied but the result is NOT assigned back.
# os.system still receives raw 'cmd'.
shlex.quote(cmd)
os.system(cmd)
