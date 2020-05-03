import pyautogui
import datetime
from struct import unpack
from time import sleep, time
from random import choice
from subprocess import Popen
from sys import exit

def chunks(l, n):
    n = max(1, n)
    return (l[i:i+n] for i in range(0, len(l), n))

with open('./assets/clutterfunk.map', 'rb') as f:
    binary = f.read()
    structs = chunks(binary, 12)

notes = []
for struct in structs:
    notes.append(unpack('=di', struct))

notes.sort(key=lambda tup: tup[0]) 

inputs = []
directions = ['a', 's', 'w', 'd']
for x in range(0, 2483):
    cent = round(x * 0.1, 1)
    group = list(filter(lambda tup: str(cent) == str(round(tup[0], 1)), notes))

    if len(group) > 0:
        inputs.append((cent, ''.join([directions[note[1]] for note in group])))

    
for note in notes:
    print(note)

for inp in inputs:
    print(inp)
#exit(0)


directions = ['left', 'down', 'up', 'right']
startup = 0.2
process = Popen(['./play', 'clutterfunk'])

sleep(startup)
start = time()
for inp in inputs:
    to_hit = start + inp[0]

    while time() < to_hit - 0.4:
        pass

    #to_sleep = inp[0] - total_time
    #sleep(to_sleep)
    #total_time += to_sleep
    pyautogui.write(inp[1])

# utflag{w0ah_d00d_u_got_some_mad_skillz_J4ebBxZpAS}
