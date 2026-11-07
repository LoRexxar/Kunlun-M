import os

def run_command(user_input):
    return user_input

payload = request.GET.get('payload')
result = run_command(payload)
os.system(result)
