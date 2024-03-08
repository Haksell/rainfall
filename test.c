#include <stdio.h>

char *p()
{
  char s[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  const void *v2; // [esp+5Ch] [ebp-Ch]
  unsigned int retaddr; // [esp+6Ch] [ebp+4h]

  fflush(stdout);
  gets(s);
  v2 = (const void *)retaddr;
  printf("%s %p %u %u\n", s, v2, retaddr, retaddr & 0xB0000000);
    _exit(1);
  if ( (retaddr & 0xB0000000) == -1342177280 )
  {
    printf("(%p)\n", v2);
    _exit(1);
  }
//   puts(s);
  return strdup(s);
}

int main() {
	p();
}