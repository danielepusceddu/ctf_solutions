#!/usr/bin/python2
#RUN THIS INSIDE OF PWNABLE.KR'S SERVER!
#Login as another user and place this file in /tmp/.
#If pwntools gives you a curses related error, set these env:
#TERM=linux
#TERMINFO=/etc/terminfo
#This script might be slightly bugged, if it doesn't work just try again.

from pwn import *

def coin_binarysearch(connection, num_coins, num_chances):
    low = 0
    high = num_coins

    for x in range(0, num_chances):
        guess = (low + high) / 2
        coins = [x for x in range(low, guess)]
        request_str = ' '.join([str(x) for x in coins])

        connection.sendline(request_str)
        #print request_str
        weight = int(connection.recvline())

        if weight % 10 == 0:
            #print 'No false coins here!'
            if len(coins) == 1:
                #print 'WHAT HAPPENED??'
                found_coin = coins[0] + 1
            else:
                low = guess

        else: #weight % 10 != 0
            #print 'False coins in the range above!'
            if len(coins) == 1:
                found_coin = coins[0]
                #print "Found coin {}".format(found_coin)
            else:
                high = guess + 1

    connection.sendline(str(found_coin))
    print connection.recvline()




#conn = remote('pwnable.kr', 9007)
conn = remote('localhost', 9007)

print 'Waiting for game start.'
conn.recvuntil('3 sec... -')

for x in range(0, 100):
    conn.recvuntil('N=')

    coin_num = int(conn.recvuntil(' ')) 
    #print 'Coin Number: {}'.format(coin_num)

    conn.recvuntil('C=')
    chances = int(conn.recvuntil('\n')) 
    #print 'Chances: {}'.format(chances)

    coin_binarysearch(conn, coin_num, chances)

conn.interactive() #Flag: b1NaRy_S34rch1nG_1s_3asy_p3asy
