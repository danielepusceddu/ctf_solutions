ln -s /home/input2/flag flag #So that "input" can cat the flag

#For file stage
printf "\x00\x0a\x00\xff" > in
printf "\x00\x0a\x02\xff" > err

#Compile and execute
gcc solution.c -o solution
./solution&

#For network stage
sleep 1
printf "\xde\xad\xbe\xef" | nc -v localhost 1337
