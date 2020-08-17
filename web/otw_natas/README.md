natas0:natas0
Just check the HTML


natas1:gtVrDuiDfck831PqWsLEZy5gyDz1clto
do the same idk


natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi
files/pixel.png
go look at files/
find users.txt


natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
"Not even Google will find it this time..."
this is a hint to go check robots.txt


natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
"Access disallowed. You are visiting from "http://natas4.natas.labs.overthewire.org/" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/""
edit the referrer parameter and resend


natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
set loggedIn cookie to 1


natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
the php source does an include "includes/secret.inc"
inspect html and there you find the secret to submit


natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
the page GET parameter seems to display the contents of a file
there are no proper controls on this parameter
use it to show /etc/natas_webpass/natas8
you can even show /etc/passwd, anything I guess


natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe
printf 3d3d516343746d4d6d6c315669563362 | xxd -r -p - | rev | base64 -d -


natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
bash command injection
just ;cat


natas10:nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
another command injection
c /etc/natas_webpass/natas11 #


natas11:U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
This uses a XOR encryption for the cookie.
We're given the source code, so we know how the original data should look like.
PLAIN ^ ENCRYPTED = KEY


natas12:EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
We can upload a file and then the server saves it with a random filename.
It doesn't control the content of the file, moreover it preserves the extension we give to it.
So just upload a php file and modify the "value" parameter of the form, changing .jpg to .php
Visit the link it gives you and your php code will be executed


natas13:jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
Same as natas12, except this time there is a control on the content, using exif_imagetype
This function simply checks the magic bytes at the beginning of a file.
So.... Let's just insert those magic bytes.
`printf '\xFF\xD8\xFF\xE0<? echo file_get_contents("/etc/natas_webpass/natas14")?>' > natas13.php`


natas14:Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
First SQL injection. just `" or 1=1 --`


natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J
Seems to be a blind injection. It tells me that "natas16" exists so we should get its password.
Check out natas15.py


natas16:WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
I solved this using a blind with bash.
You can insert an if block with newlines, and use head -c to get natas17's password character by character.
Be careful, the shell seems to be 100% posix compliant only. Therefore, == and such don't work.


natas17:8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
Same as natas15, except there is no output this time around. Let's use sleep.


natas18:xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
PHPSESSID is set to low values. Max is 640. Easy to bruteforce.


natas19:4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs
Similar to natas18, but PHPSESSID is not as simple.
Trying usernames such as "natas17", "natas18", etc. I saw that they were all very similar to each other.
Turns out that PHPSESSID is just hex-encoded "<number>-<username>". <number> was always relatively low so I assume the max is still 640. I tried bruteforcing with "<number>-admin"


natas20:eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF
This challenge implements its own read / write functions for the session files. Just set your username to "username\nadmin 1". Read will take that second line as a session variable.


natas21:IFekPyrQXftziDEsUr3x21sYuahypdgJ
You will be given a "colocated" site. That site allows you to set SESSION variables. Send a POST request with admin=1, then change your PHPSESSID in the main site.


natas22:chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ
Do not follow redirects! If you set revelio, the site will print the flag but you instantly get redirected to the homepage.


natas23:D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE
`if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 ))`
strstr checks if the string contains "iloveyou". Also I assumed that the conversion into a number stopped at the first non-digit character.
So, just input `11iloveyou` and you'll get the flag.


natas24:OsRmXFguozKpTZZ5X14zNO43379LZveg
After a bit of googling I found out that php's strcmp is very unreliable when one of the parameters isn't a string.
We can make it so that passwd is an array by sending it as `?passwd[]` in the URL bar.


natas25:GHF6X7YwACaYYssHVY05cFq83hRktl4c
The custom `safe_include()` function simply uses a blacklist to try and prevent path traversal.
As we all know, blacklists are bad. I visited PayloadAllTheThings and found `....//` to escape filters.
It seems to work, `?lang=....//index-source.html` gives me the source of the page.
I noticed that `include()` executes php code, so if we could include an input of ours, we can have RCE.
`logRequest` will serve this purpose: it outputs our user agent to a log file. Change the user agent to php code and include the log file.
```
GET /?lang=....//logs/natas25_<your_session_id>.log HTTP/1.1
User-Agent: <?php echo(file_get_contents("/etc/natas_webpass/natas26")); ?>
```

natas26:oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T

