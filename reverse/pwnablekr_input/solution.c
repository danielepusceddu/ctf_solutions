#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/*PROUDLY MADE WITH VIM!*/
/* For argv stage */
char* const args[] = {"a", "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "\x00", "\x20\x0a\x0d", "1337",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a",  "a", NULL};

/* For env stage */
char* const envp[] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};

int main(){
    /*For stdio stage*/
    int newIn = open("in", O_RDONLY);
    int newErr = open("err", O_RDONLY);

    dup2(newIn, 0);
    dup2(newErr, 2);

    /* For file stage, see also solve.sh */
    FILE* fp = fopen("\x0a", "w+");
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);

    execve("/home/input2/input", args, envp); 
    return 0;
}

