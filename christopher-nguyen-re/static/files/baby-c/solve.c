#include <ctype.h>
#include <stdio.h>

int main() {
  // glhf
  char flag;
  int letter;
  
  flag = 1;
  while (1)
  {
    letter = getc(stdin);
  
    if (letter == -1)
    {
      break;
    }

    if (isspace(letter) != 0)
    {
     putc(letter, stdout);
     flag = 1;
    }
    else
    {
      if (flag != 0)
      {
        putc(toupper(letter), stdout);
        flag = 0;
      }
      else
      {
        putc(tolower(letter), stdout);
      }
    }
  }

  return 0;
}