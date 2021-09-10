#include "defs.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void __noreturn error(const char *a1)
{
  __printf_chk(1LL, "ERROR: %s\n", a1);
  exit(1);
}

// goes in infinite loop when dim is negative
int printhex(unsigned __int8 *arr, __int64 dim)
{
  unsigned __int8 *v2; // rbx
  __int64 v3; // rdx

  if ( dim )
  {
    v2 = arr;
    do
    {
      v3 = *v2++;
      __printf_chk(1LL, "%02x", v3);
    }
    while ( v2 != &arr[dim] );
  }
  return putchar(10);
}

__int64 chrdehex(char a1)
{
  // all ok
  if ( (unsigned __int8)(a1 - '0') <= 9u )
    return a1 - (unsigned int)'0';
  if ( (unsigned __int8)(a1 - 'a') <= 5u )
    return a1 - (unsigned int)'W';
  if ( (unsigned __int8)(a1 - 'A') > 5u )
    error("invalid hexadecimal digit");
  return a1 - (unsigned int)'7';
}

unsigned __int64 dehex(char *hexstr)
{
  __int64 v2; // rdi
  unsigned __int64 hexI; // rbp
  char upper; // bl
  char lower; // al
  unsigned __int64 hexIcp; // rdx

  v2 = (unsigned int)*hexstr;
  if ( !(_BYTE)v2 )
    return 0LL;
  hexI = 0LL;
  do
  {
    upper = chrdehex(v2);
    lower = chrdehex((unsigned int)hexstr[hexI + 1]);
    hexIcp = hexI;
    hexI += 2LL;
    hexstr[hexIcp >> 1] = lower + 16 * upper;
    v2 = (unsigned int)hexstr[hexI];
  }
  while ( hexstr[hexI] );
  return hexI >> 1;
}

unsigned __int64 compress_part_0(char *out, unsigned __int64 outDim, char *inp, unsigned __int64 inpLen)
{
  unsigned __int64 outInd; // r12
  unsigned __int64 inpInd; // rbp
  char *inpSub; // rsi
  unsigned __int64 v11; // r13
  unsigned __int64 repeats; // r9
  unsigned __int64 i; // rcx
  unsigned __int64 patternLen; // rax
  char v15; // al
  unsigned __int64 v17; // rdx
  unsigned __int64 v18; // rdx
  unsigned __int64 commandInd; // rax
  char v20; // cl
  unsigned __int64 v21; // rcx
  char v22; // al

  if ( inpLen )
  {
    outInd = 4LL;
    inpInd = 0LL;
    while ( 1 )
    {
      if ( !inpInd )
        goto LABEL_13;
      inpSub = inp;
      v11 = 0LL;
      repeats = 0LL;
      for ( i = 0LL; i != inpInd; ++i )
      {
        if ( inpLen > i )
        {
          patternLen = 0LL;
          do
          {
            if ( inpSub[patternLen] != inp[inpInd + patternLen] )
              break;
            ++patternLen;
          }
          while ( inpLen > patternLen + i );
          if ( patternLen > repeats )
          {
            v11 = i;
            repeats = patternLen;
          }
        }
        ++inpSub;
      }
      if ( repeats > 3 )
      {
        v17 = inpInd;
        inpInd += repeats;
        v18 = v17 - v11;
        if ( outDim <= outInd )
          goto DEST_OVERFLOW;
        out[outInd] = -1;                       // insert command
        commandInd = outInd + 1;
        while ( v18 > 0x7F )
        {
          if ( commandInd >= outDim )
            goto DEST_OVERFLOW;
          v20 = v18;
          v18 >>= 7;
          out[commandInd++] = v20 | 0x80;
        }
        if ( commandInd >= outDim )
          goto DEST_OVERFLOW;
        out[commandInd] = v18;
        v21 = commandInd + 1;
        if ( repeats > 0x7F )
        {
          while ( outDim > v21 )
          {
            v22 = repeats;
            ++v21;
            repeats >>= 7;
            out[v21 - 1] = v22 | 0x80;
            if ( repeats <= 0x7F )
              goto LABEL_29;
          }
          goto DEST_OVERFLOW;
        }
LABEL_29:
        if ( outDim <= v21 )
          goto DEST_OVERFLOW;
        out[v21] = repeats;
        outInd = v21 + 1;
      }
      else
      {
LABEL_13:
        if ( outDim <= outInd )
          goto DEST_OVERFLOW;
        v15 = inp[inpInd++];
        out[outInd++] = v15;
      }
      if ( inpLen <= inpInd )
        goto CHECK_DEST_OVERFLOW_END;
    }
  }
  outInd = 4LL;
CHECK_DEST_OVERFLOW_END:
  if ( outDim <= outInd || (out[outInd] = -1, outDim <= outInd + 1) || (out[outInd + 1] = 0, outDim <= outInd + 2) )
DEST_OVERFLOW:
    error("destination overflow");
  out[outInd + 2] = 0;
  return outInd + 3;
}

unsigned __int64 decompress(char *output, unsigned __int64 outputDim, _BYTE *input, unsigned __int64 inputLen)
{
  unsigned __int64 outInd; // r12
  __int64 chInd; // rdx
  unsigned __int64 nextChInd; // rax
  char currCh; // dl
  int toShift; // ecx
  __int64 patternLen; // r9
  unsigned __int64 signedShifted; // rdx
  int v14; // ecx
  __int64 bytesToWrite; // rbx
  unsigned __int64 v16; // rdx
  char *outIt; // rdx
  char v18; // cl

  if ( !inputLen )
    goto INPUT_UNDERFLOW;
  if ( *input != 0x54 )
    goto BAD_MAGIC;
  if ( inputLen <= 1 )
    goto INPUT_UNDERFLOW;
  if ( input[1] != 0x49 )
    goto BAD_MAGIC;
  if ( inputLen == 2 )
    goto INPUT_UNDERFLOW;
  if ( input[2] != 0x4E )
    goto BAD_MAGIC;
  if ( inputLen == 3 )
    goto INPUT_UNDERFLOW;
  if ( input[3] != 0x59 )
BAD_MAGIC:
    error("bad magic");
  if ( inputLen == 4 )
INPUT_UNDERFLOW:
    error("input underflow");
  outInd = 0LL;
  chInd = 4LL;
  while ( 1 )
  {
    nextChInd = chInd + 1;
    currCh = input[chInd];
    if ( currCh != (char)0xFF )
    {
      if ( outInd >= outputDim )
        goto DEST_OVERFLOW;
      output[outInd++] = currCh;
      chInd = nextChInd;
      goto CYCLE_FOOTER;
    }
    toShift = 0;
    patternLen = 0LL;
    do
    {
      if ( nextChInd >= inputLen )
        goto INPUT_UNDERFLOW;
      // take only the signed part and shift it
      signedShifted = (unsigned __int64)(input[nextChInd++] & 0x7F) << toShift;
      toShift += 7;
      patternLen |= signedShifted;
    }
    while ( (char)input[nextChInd - 1] < 0 );
    v14 = 0;
    bytesToWrite = 0LL;
    do
    {
      if ( nextChInd >= inputLen )
        goto INPUT_UNDERFLOW;
      v16 = (unsigned __int64)(input[nextChInd++] & 0x7F) << v14;
      v14 += 7;
      bytesToWrite |= v16;
    }
    while ( (char)input[nextChInd - 1] < 0 );
    if ( !patternLen )
      break;
    if ( bytesToWrite )
    {
      outIt = &output[outInd - patternLen];
      do
      {
        v18 = *outIt++;
        outIt[patternLen - 1] = v18;
      }
      while ( outIt != &output[outInd - patternLen + bytesToWrite] );
      outInd += bytesToWrite;
      chInd = nextChInd;
    }
    else
    {
      chInd = nextChInd;
    }
CYCLE_FOOTER:
    if ( inputLen <= nextChInd )
      goto INPUT_UNDERFLOW;
  }
  if ( bytesToWrite )
  {
    if ( bytesToWrite != 1 )
      error("invalid special command");
    if ( outInd >= outputDim )
DEST_OVERFLOW:
      error("destination overflow");
    output[outInd] = -1;
    chInd = nextChInd;
    ++outInd;
    goto CYCLE_FOOTER;
  }
  return outInd;
}

unsigned __int64 compress(_BYTE *output, unsigned __int64 outDim, char *inp, unsigned __int64 a4)
{
  // this is completely useless 
  // and does not seem to be giving any hints
  // i think they just forgot this function here
  if ( !outDim || (*output = 84, outDim <= 1) || (output[1] = 73, outDim == 2) || (output[2] = 78, outDim == 3) )
    error("destination overflow");
  output[3] = 0x59;
  return compress_part_0(output, outDim, inp, a4);
}

int main(int argc, const char **argv, const char **envp)
{
  FILE *pswdFile; // rax
  unsigned __int64 nBytesInp; // r12
  __int64 nBytesCompr; // rax
  __int64 v7; // rbp
  double v8; // xmm0_8
  double v9; // xmm0_8
  double nBytesInpDoubl; // xmm1_8
  unsigned __int64 numBytes; // rax
  unsigned __int64 numDecompressed; // rbp
  int option; // [rsp+Ch] [rbp-333Ch] BYREF
  char command[256]; // [rsp+10h] [rbp-3338h] BYREF
  char pswdInp[256]; // [rsp+110h] [rbp-3238h] BYREF
  char pswd[256]; // [rsp+210h] [rbp-3138h] BYREF
  char input[8192]; // [rsp+310h] [rbp-3038h] BYREF
  char out[4096]; // [rsp+2310h] [rbp-1038h] BYREF
  // unsigned __int64 canary; // [rsp+3318h] [rbp-30h]

  // canary = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);

  strcpy(command, "cat FORMAT.md");
  puts("What can I do for you?");
  puts("1. Compress string");
  puts("2. Decompress string");
  puts("3. Read compression format documentation");
  putchar(10);
  option = 0;
  if ( (unsigned int)__isoc99_scanf("%d", &option) != 1 )
    goto INVALID_CHOICE;

  if ( option == 1 )
  {
    puts("Send me the hex-encoded string (max 4k):");
    __isoc99_scanf("%8000s", input);
    nBytesInp = dehex(input);
    *(_DWORD *)out = 0x594E4954;                // magic number
    nBytesCompr = compress_part_0(out, 0xFA0uLL, input, nBytesInp);
    v7 = nBytesCompr;
    if ( nBytesCompr < 0 )
      v8 = (double)(int)(nBytesCompr & 1 | ((unsigned __int64)nBytesCompr >> 1))
         + (double)(int)(nBytesCompr & 1 | ((unsigned __int64)nBytesCompr >> 1));
    else
      v8 = (double)(int)nBytesCompr;
    v9 = v8 * 100.0;
    if ( (nBytesInp & 0x8000000000000000LL) != 0LL )
      nBytesInpDoubl = (double)(int)(nBytesInp & 1 | (nBytesInp >> 1)) + (double)(int)(nBytesInp & 1 | (nBytesInp >> 1));
    else
      nBytesInpDoubl = (double)(int)nBytesInp;
    __printf_chk(1LL, "These %zu bytes compress to %zu bytes (%.2lf%%):\n", nBytesInp, nBytesCompr, v9 / nBytesInpDoubl);
    printhex((unsigned __int8 *)out, v7);
    return 0;
  }
  if ( option == 2 )
  {
    puts("Send me the hex-encoded string (max 4k):");
    __isoc99_scanf("%8000s", input);
    numBytes = dehex(input);
    numDecompressed = decompress(out, 4000uLL, input, numBytes);
    puts("That decompresses to:");
    printhex((unsigned __int8 *)out, numDecompressed);
    return 0;
  }
  if ( option != 3 )
INVALID_CHOICE:
    error("invalid choice");
  puts("Format documentation is password protected.");
  puts("Input password:");
  __isoc99_scanf("%100s", pswdInp);
  pswdFile = fopen("FORMAT.md.password", "r");
  __isoc99_fscanf(pswdFile, "%s", pswd);
  if ( strcmp(pswdInp, pswd) )
    error("wrong password");
  system(command);
  return 0;
}