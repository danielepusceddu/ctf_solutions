#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define die(e) do { fprintf(stderr, "%s\n", e);  } while (0);

int main() {
  int parent2child[2];
  pid_t pid;

  signal(SIGALRM, SIG_IGN);

  if (pipe(parent2child) == -1)
      die("pipe2");

  if ((pid = fork()) == -1)
    die("fork");

  if(pid == 0) { //Child
    dup2(parent2child[0], STDIN_FILENO);

    //write(parent2child[1], "0\n", 2);
    close(parent2child[0]);
    close(parent2child[1]);
    execl("./times-up-one-last-time", "times-up-one-last-time", NULL);
    //execl("./notimer", "notimer", NULL);
    die("execl");

  } else {
    close(parent2child[0]);

    //writing solution
    int written = write(parent2child[1], "0\n", 2); 

  }
  return 0;
}
