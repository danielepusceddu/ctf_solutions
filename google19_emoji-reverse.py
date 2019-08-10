#beginner's google ctf 2019
#emoji-reversing 'FriendSpaceBookPlusAllAccessRedPremium'

#We are given a program written entirely in emoji and a VM to execute it.
#When we execute it, we see that it starts writing an URL but it starts being way too slow due to excessive amounts of computations.
#In the code, we see that it prints each character right before doing a xor.
#Using a debugger we can see that the XORs are always done between a prime palindromic number and a number loaded on the stack by the program.
#We can use this information to bruteforce all of the characters.

import string

#For the first block of numbers loaded onto the stack, we simply use a list of palindromic primes. It's the first 40 numbers so it's easy this way.
def first_block():
    xor_nums = [106, 119, 113, 119, 49, 74, 172, 242, 216, 208, 339, 264, 344, 267, 743, 660, 893, 892, 1007, 975, 10319, 10550, 10503, 11342, 11504, 12533, 12741, 12833, 13437, 13926, 13893, 14450, 14832, 15417, 15505, 16094, 16285, 16599, 16758, 17488] 
    first_palindromic_primes = [2, 3, 5, 7, 11, 101, 131, 151, 181, 191, 313, 353, 373, 383, 727, 757, 787, 797, 919, 929, 10301, 10501, 10601, 11311, 11411, 12421, 12721, 12821, 13331, 13831, 13931, 14341, 14741, 15451, 15551, 16061, 16361, 16561, 16661, 17471]

    zipped = zip(xor_nums, first_palindromic_primes)

    for tup in zipped:
        ascii_code = tup[0] ^ tup[1]
        print(chr(ascii_code), end='')

def is_palindrome(x):
    x_str = str(x)
    x_str_reverse = ''.join(reversed(x_str))

    return x_str == x_str_reverse

#For the 2 other blocks, we use bruteforcing.
#We xor each number on the stack with a character and see if it gives us a palindrome.
#If it does, it is very likely that it's the character of the url.
#In case we find multiple palindromes for a single stack number, we will put the other characters between square brackets.
#It will happen only once.
def second_third_block():
    url_chars = string.ascii_letters + string.digits + '/:._;?@=&$-+!*\'(),'
    xor_nums = [93766, 93969, 94440, 94669, 94952, 94865, 95934, 96354, 96443, 96815, 97280, 97604, 97850, 98426, 9916239, 9918082, 9919154, 9921394, 9923213, 9926376, 9927388, 9931494, 9932289, 9935427, 9938304, 9957564, 9965794, 9978842, 9980815, 9981858, 9989997, 100030045, 100049982, 100059926, 100111100, 100131019, 100160922, 100404094, 100656111, 100707036, 100767085, 100887990, 100998966, 101030055, 101060206, 101141058]
    for num in xor_nums:
        found_chars = []
        for char in url_chars:
            xor = ord(char) ^ num

            if is_palindrome(xor):
                found_chars.append(char)
        
        if len(found_chars) == 0:
            print('{NONE}')
        elif len(found_chars) == 1:
            print(found_chars[0], end='')
        else:
            print('[' + ''.join(found_chars) + ']', end='')

    print('\n', end='')

if __name__ == '__main__':
    print('Characters between square brackets means that you need to choose only one of those characters.')
    print('A {NONE} means that there is a missing character in the url.\n')
    first_block()
    second_third_block()
    print('\nGo look around this web page and you\'ll find your flag quickly!')
