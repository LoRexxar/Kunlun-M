import os
data = request.GET.get('data')
data = shlex.quote(data)
os.system(data)