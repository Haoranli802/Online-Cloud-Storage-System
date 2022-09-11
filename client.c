// Weiyu Hao, 59955246
// Haoran Li, 80921159

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef unsigned long int UINT4;

/* Data structure for MD5 (Message Digest) computation */
typedef struct {
  UINT4 i[2];                   /* number of _bits_ handled mod 2^64 */
  UINT4 buf[4];                                    /* scratch buffer */
  unsigned char in[64];                              /* input buffer */
  unsigned char digest[16];     /* actual digest after MD5Final call */
} MD5_CTX;

/* forward declaration */
static void Transform ();

static unsigned char PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* F, G and H are basic MD5 functions: selection, majority, parity */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z))) 

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
   (a) = ROTATE_LEFT ((a), (s)); \
   (a) += (b); \
  }

void MD5Init (mdContext)
MD5_CTX *mdContext;
{
  mdContext->i[0] = mdContext->i[1] = (UINT4)0;

  /* Load magic initialization constants.
   */
  mdContext->buf[0] = (UINT4)0x67452301;
  mdContext->buf[1] = (UINT4)0xefcdab89;
  mdContext->buf[2] = (UINT4)0x98badcfe;
  mdContext->buf[3] = (UINT4)0x10325476;
}

void MD5Update (mdContext, inBuf, inLen)
MD5_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* update number of bits */
  if ((mdContext->i[0] + ((UINT4)inLen << 3)) < mdContext->i[0])
    mdContext->i[1]++;
  mdContext->i[0] += ((UINT4)inLen << 3);
  mdContext->i[1] += ((UINT4)inLen >> 29);

  while (inLen--) {
    /* add new character to buffer, increment mdi */
    mdContext->in[mdi++] = *inBuf++;

    /* transform if necessary */
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
                (((UINT4)mdContext->in[ii+2]) << 16) |
                (((UINT4)mdContext->in[ii+1]) << 8) |
                ((UINT4)mdContext->in[ii]);
      Transform (mdContext->buf, in);
      mdi = 0;
    }
  }
}

void MD5Final (mdContext)
MD5_CTX *mdContext;
{
  UINT4 in[16];
  int mdi;
  unsigned int i, ii;
  unsigned int padLen;

  /* save number of bits */
  in[14] = mdContext->i[0];
  in[15] = mdContext->i[1];

  /* compute number of bytes mod 64 */
  mdi = (int)((mdContext->i[0] >> 3) & 0x3F);

  /* pad out to 56 mod 64 */
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  MD5Update (mdContext, PADDING, padLen);

  /* append length in bits and transform */
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((UINT4)mdContext->in[ii+3]) << 24) |
            (((UINT4)mdContext->in[ii+2]) << 16) |
            (((UINT4)mdContext->in[ii+1]) << 8) |
            ((UINT4)mdContext->in[ii]);
  Transform (mdContext->buf, in);

  /* store buffer in digest */
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    mdContext->digest[ii] = (unsigned char)(mdContext->buf[i] & 0xFF);
    mdContext->digest[ii+1] =
      (unsigned char)((mdContext->buf[i] >> 8) & 0xFF);
    mdContext->digest[ii+2] =
      (unsigned char)((mdContext->buf[i] >> 16) & 0xFF);
    mdContext->digest[ii+3] =
      (unsigned char)((mdContext->buf[i] >> 24) & 0xFF);
  }
}

/* Basic MD5 step. Transform buf based on in.
 */
static void Transform (buf, in)
UINT4 *buf;
UINT4 *in;
{
  UINT4 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

  /* Round 1 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
  FF ( a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
  FF ( d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
  FF ( c, d, a, b, in[ 2], S13,  606105819); /* 3 */
  FF ( b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
  FF ( a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
  FF ( d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
  FF ( c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
  FF ( b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
  FF ( a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
  FF ( d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
  FF ( c, d, a, b, in[10], S13, 4294925233); /* 11 */
  FF ( b, c, d, a, in[11], S14, 2304563134); /* 12 */
  FF ( a, b, c, d, in[12], S11, 1804603682); /* 13 */
  FF ( d, a, b, c, in[13], S12, 4254626195); /* 14 */
  FF ( c, d, a, b, in[14], S13, 2792965006); /* 15 */
  FF ( b, c, d, a, in[15], S14, 1236535329); /* 16 */

  /* Round 2 */
#define S21 5
#define S22 9
#define S23 14
#define S24 20
  GG ( a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
  GG ( d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
  GG ( c, d, a, b, in[11], S23,  643717713); /* 19 */
  GG ( b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
  GG ( a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
  GG ( d, a, b, c, in[10], S22,   38016083); /* 22 */
  GG ( c, d, a, b, in[15], S23, 3634488961); /* 23 */
  GG ( b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
  GG ( a, b, c, d, in[ 9], S21,  568446438); /* 25 */
  GG ( d, a, b, c, in[14], S22, 3275163606); /* 26 */
  GG ( c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
  GG ( b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
  GG ( a, b, c, d, in[13], S21, 2850285829); /* 29 */
  GG ( d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
  GG ( c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
  GG ( b, c, d, a, in[12], S24, 2368359562); /* 32 */

  /* Round 3 */
#define S31 4
#define S32 11
#define S33 16
#define S34 23
  HH ( a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
  HH ( d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
  HH ( c, d, a, b, in[11], S33, 1839030562); /* 35 */
  HH ( b, c, d, a, in[14], S34, 4259657740); /* 36 */
  HH ( a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
  HH ( d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
  HH ( c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
  HH ( b, c, d, a, in[10], S34, 3200236656); /* 40 */
  HH ( a, b, c, d, in[13], S31,  681279174); /* 41 */
  HH ( d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
  HH ( c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
  HH ( b, c, d, a, in[ 6], S34,   76029189); /* 44 */
  HH ( a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
  HH ( d, a, b, c, in[12], S32, 3873151461); /* 46 */
  HH ( c, d, a, b, in[15], S33,  530742520); /* 47 */
  HH ( b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

  /* Round 4 */
#define S41 6
#define S42 10
#define S43 15
#define S44 21
  II ( a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
  II ( d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
  II ( c, d, a, b, in[14], S43, 2878612391); /* 51 */
  II ( b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
  II ( a, b, c, d, in[12], S41, 1700485571); /* 53 */
  II ( d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
  II ( c, d, a, b, in[10], S43, 4293915773); /* 55 */
  II ( b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
  II ( a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
  II ( d, a, b, c, in[15], S42, 4264355552); /* 58 */
  II ( c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
  II ( b, c, d, a, in[13], S44, 1309151649); /* 60 */
  II ( a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
  II ( d, a, b, c, in[11], S42, 3174756917); /* 62 */
  II ( c, d, a, b, in[ 2], S43,  718787259); /* 63 */
  II ( b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

/*
 **********************************************************************
 ** End of md5.c                                                     **
 ******************************* (cut) ********************************
 */

/*
 **********************************************************************
 ** md5driver.c -- sample routines to test                           **
 ** RSA Data Security, Inc. MD5 message digest algorithm.            **
 ** Created: 2/16/90 RLR                                             **
 ** Updated: 1/91 SRD                                                **
 **********************************************************************
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **                                                                  **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.             **
 **                                                                  **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.                                   **
 **********************************************************************
 */

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
/* -- include the following file if the file md5.h is separate -- */
/* #include "md5.h" */

/* Prints message digest buffer in mdContext as 32 hexadecimal digits.
   Order is from low-order byte to high-order byte of digest.
   Each byte is printed with high-order hexadecimal digit first.
 */
static void MDPrint (mdContext)
MD5_CTX *mdContext;
{
  int i;

  for (i = 0; i < 16; i++)
    printf ("%02x", mdContext->digest[i]);
}

/* size of test block */
#define TEST_BLOCK_SIZE 1000

/* number of blocks to process */
#define TEST_BLOCKS 10000

/* number of test bytes = TEST_BLOCK_SIZE * TEST_BLOCKS */
static long TEST_BYTES = (long)TEST_BLOCK_SIZE * (long)TEST_BLOCKS;

/* A time trial routine, to measure the speed of MD5.
   Measures wall time required to digest TEST_BLOCKS * TEST_BLOCK_SIZE
   characters.
 */
static void MDTimeTrial ()
{
  MD5_CTX mdContext;
  time_t endTime, startTime;
  unsigned char data[TEST_BLOCK_SIZE];
  unsigned int i;

  /* initialize test data */
  for (i = 0; i < TEST_BLOCK_SIZE; i++)
    data[i] = (unsigned char)(i & 0xFF);

  /* start timer */
  printf ("MD5 time trial. Processing %ld characters...\n", TEST_BYTES);
  time (&startTime);

  /* digest data in TEST_BLOCK_SIZE byte blocks */
  MD5Init (&mdContext);
  for (i = TEST_BLOCKS; i > 0; i--)
    MD5Update (&mdContext, data, TEST_BLOCK_SIZE);
  MD5Final (&mdContext);

  /* stop timer, get time difference */
  time (&endTime);
  MDPrint (&mdContext);
  printf (" is digest of test input.\n");
  printf
    ("Seconds to process test input: %ld\n", (long)(endTime-startTime));
  printf
    ("Characters processed per second: %ld\n",
     TEST_BYTES/(endTime-startTime));
}

/* Computes the message digest for string inString.
   Prints out message digest, a space, the string (in quotes) and a
   carriage return.
 */
static void MDString (inString)
char *inString;
{
  MD5_CTX mdContext;
  unsigned int len = strlen (inString);

  MD5Init (&mdContext);
  MD5Update (&mdContext, inString, len);
  MD5Final (&mdContext);
  MDPrint (&mdContext);
  printf (" \"%s\"\n\n", inString);
}

/* Computes the message digest for a specified file.
   Prints out message digest, a space, the file name, and a carriage
   return.
 */

/* Writes the message digest of the data from stdin onto stdout,
   followed by a carriage return.
 */
static void MDFilter ()
{
  MD5_CTX mdContext;
  int bytes;
  unsigned char data[16];

  MD5Init (&mdContext);
  while ((bytes = fread (data, 1, 16, stdin)) != 0)
    MD5Update (&mdContext, data, bytes);
  MD5Final (&mdContext);
  MDPrint (&mdContext);
  printf ("\n");
}



/*
 **********************************************************************
 ** End of md5driver.c                                               **
 ******************************* (cut) ********************************
 */

#define MAXLINE 80
#define PORT 9999

int inputParser(char* commandLine, char** argcs){
    int token_count = 0;
    argcs[0] = strtok(commandLine," \n\t\r");

    token_count ++;
    while((argcs[token_count] = strtok(NULL, " \n\t\r")) != NULL){
        token_count ++;
    }
    return token_count;
}

// Sending an entire file to the server.
int sending(int client_socket, char* file_path){
    FILE *fptr;
    int chunk_size = 1000;
    char file_chunk[chunk_size];
    fptr = fopen(file_path,"rb");  // Open a file in read-binary mode.
    fseek(fptr, 0L, SEEK_END);  // Sets the pointer at the end of the file.
    int file_size = ftell(fptr);  // Get file size.
    char str[MAXLINE];
    sprintf(str, "%d", file_size);
    send(client_socket, str, strlen(str), 0);
    bzero(str, sizeof(str));
    recv(client_socket, str, MAXLINE, 0);

    //printf("str %s\n", str);

    //printf("Client: file size = %i bytes\n", file_size);
    fseek(fptr, 0L, SEEK_SET);  // Sets the pointer back to the beginning of the file.
    int total_bytes = 0;  // Keep track of how many bytes we read so far.
    int current_chunk_size;  // Keep track of how many bytes we were able to read from file (helpful for the last chunk).
    ssize_t sent_bytes;
    while (total_bytes < file_size){
        bzero(file_chunk, chunk_size);
        // Read file bytes from file.
        int current_chunk_size = fread(&file_chunk, sizeof(char), chunk_size, fptr);
        // Sending a chunk of file to the socket.
        int sent_bytes = send(client_socket, &file_chunk, current_chunk_size, 0);
        // Keep track of how many bytes we read/sent so far.
        total_bytes = total_bytes + sent_bytes;
        //printf("Client: sent to client %i bytes. Total bytes sent so far = %i.\n", sent_bytes, total_bytes);
        printf("%i bytes uploaded successfully.\n",total_bytes);
    }
    fclose(fptr);
    return 0;
}

// append mode
int append_mode(int client_socket, char* line){
    char* tokens[80];
    char buf[MAXLINE];
    printf("Appending> %s\n", line);
    char* copy = NULL;
    copy = (char *) malloc( strlen(line) + 1 ); 
    strcpy( copy, line );
    //printf("message received : %s", copy);
    
    if(strcmp(line, "") == 0){
        return 0;
    }
    if(strcmp(line, "\n") == 0){
        return 0;
    }
    inputParser(line, tokens);
    if(strcmp(tokens[0], "close") == 0){
      write(client_socket, "close", strlen("close"));
      bzero(buf, sizeof(buf));
      recv(client_socket, buf, MAXLINE, 0);
      bzero(buf, sizeof(buf));
      return 1;
    }
    else if(strcmp(tokens[0], "pause") == 0){
        sleep(atoi(tokens[1]));
        return 0;
    }
    else{
        write(client_socket, copy, strlen(copy));
        bzero(buf, sizeof(buf));
        recv(client_socket, buf, MAXLINE, 0);
        bzero(buf, sizeof(buf));
        return 0;
    }
    free(copy);
    
}

// Receiving an entire file.
int receiving(int client_socket, char* file_name){
    char buf[MAXLINE];
    bzero(buf, sizeof(buf));
    read(client_socket, buf, MAXLINE);
    //printf("%s\n", buf);
    if(strcmp(buf, "yes") == 0){
        send(client_socket, "downloading", strlen("downloading"), 0);
        //check lock
        char message[MAXLINE];
        bzero(message,sizeof(message));
        recv(client_socket, message, MAXLINE, 0);
        //printf("return message: %s",message);
        if(strcmp(message,"no")==0){
          printf("File [%s] is currently locked by another user.\n",file_name);
          return 0;
        }
        //sleep(1);
        
        send(client_socket, "downloading", strlen("downloading"), 0);
        int received_size;
        char path[1024];
        bzero(path, sizeof(path));
        char destination_path[256];
        bzero(destination_path, sizeof(destination_path));
        strcat(destination_path, "/Local\ Directory/");
        strcat(destination_path, file_name);
        getcwd(path, MAXLINE);
        strcat(path, destination_path);
      
        int chunk_size = 1000;
        char file_chunk[chunk_size];
        bzero(file_chunk, sizeof(file_chunk));

        char temp[MAXLINE];
        bzero(temp, sizeof(temp));
        recv(client_socket, temp, MAXLINE, 0);
        int file_size = atoi(temp);

        send(client_socket, "downloading", strlen("downloading"), 0);

        printf("%d bytes downloaded successfully.\n", file_size);
        //printf("path: %s", path);
        FILE *fptr;
        // Opening a new file in write-binary mode to write the received file bytes into the disk using fptr.
        fptr = fopen(path, "wb");
        int received_bytes;
        int total_bytes = 0;
        // Keep receiving bytes until we receive the whole file.
        while (1){
          bzero(file_chunk, chunk_size);
          int remaining_bytes = file_size - total_bytes;
          if (remaining_bytes <= chunk_size){
              received_bytes = recv(client_socket, file_chunk, remaining_bytes, 0);
              fwrite(&file_chunk, sizeof(char), received_bytes, fptr);
              break;
          }
          received_bytes = recv(client_socket, file_chunk, chunk_size, 0);
          total_bytes = total_bytes + received_bytes;
          fwrite(&file_chunk, sizeof(char), received_bytes, fptr);
        }
        fclose(fptr);
    }
    else{
        printf("File [%s] could not be found in remote directory.\n", file_name);
    }
    return 0;
}

char* MDFile (char* filename)
{
  FILE *inFile = fopen (filename, "rb");
  MD5_CTX mdContext;
  int bytes;
  unsigned char data[1024];

  if (inFile == NULL) {
    printf ("%s can't be opened.\n", filename);
    return -1;
  }

  MD5Init (&mdContext);
  while ((bytes = fread (data, 1, 1024, inFile)) != 0)
    MD5Update (&mdContext, data, bytes);
  MD5Final (&mdContext);
  //MDPrint (&mdContext);
  //printf (" %s\n", filename);
  int i;
  static char result[33];
  bzero(result, sizeof (result));
  for (i = 0; i < 16; i++){
    char temp[3];
    sprintf(temp,"%02x\0",mdContext.digest[i]);
    strcat(result, temp);
  }
  
  //printf ("tested %s\n", result);
  result[32] = '\0';
  
  fclose (inFile);
  return result;
}

int syncheck(int client_socket, char* file_name){
    printf("Sync Check Report:\n");
    
    char path[256];
    char destination_path[MAXLINE] = "/Local\ Directory/";
    strcat(destination_path, file_name);
    getcwd(path, MAXLINE);
    strcat(path, destination_path);
    //printf("%s\n", path);
    
    char inRemote[MAXLINE];
    bzero(inRemote,sizeof(inRemote));
    read(client_socket, inRemote, MAXLINE);
    send(client_socket, "synchecking", strlen("synchecking"), 0);
    //printf("2");
    
    
    if (access(path, F_OK) == 0) {
        printf("- Local Directory:\n");
        FILE *fptr;
        fptr = fopen(path,"rb");  // Open a file in read-binary mode.
        fseek(fptr, 0L, SEEK_END);  // Sets the pointer at the end of the file.
        int file_size = ftell(fptr);  // Get file size.
        fclose(fptr);
        printf("-- File Size: %d bytes.\n",file_size);
        //printf("%s\n",inRemote);
        if(strcmp(inRemote,"yes")==0){
            printf("- Remote Directory:\n");
            char file_size[MAXLINE];
            bzero(file_size,sizeof(file_size));
            read(client_socket, file_size, MAXLINE);
            printf("-- File Size: %d bytes.\n",atoi(file_size));

            send(client_socket, "inRemote", strlen("inRemote"), 0);

            char remoteHash[33];
            bzero(remoteHash,sizeof(remoteHash));
            // printf("%i\n", localHash);
            read(client_socket, remoteHash, 32);
            remoteHash[32] = '\0';
            // printf("%i\n", atoi(remoteHash));
            //printf("localHash: %s\n",MDFile(path));
            //printf("remoteHash: %s\n",remoteHash);
            if(strcmp(remoteHash, MDFile(path))==0){
                printf("-- Sync Status: synced.\n");
            }
            else{
                printf("-- Sync Status: unsynced.\n");
            }
            send(client_socket, "inRemote", strlen("inRemote"), 0);
            char lockMessage[MAXLINE];
            bzero(lockMessage,sizeof(lockMessage));
            read(client_socket,lockMessage,MAXLINE);
            if(strcmp(lockMessage,"yes")==0){
              printf("-- Lock Status: locked.\n");
            }
            else{
              printf("-- Lock Status: unlocked.\n");
            }
        }
    }
    
    else{
        if(strcmp(inRemote,"yes")==0){
            printf("- Remote Directory:\n");
            char file_size[MAXLINE];
            read(client_socket, file_size, MAXLINE);
            send(client_socket, "inRemote", strlen("inRemote"), 0);
            printf("-- File Size: %d bytes.\n", atoi(file_size));
            bzero(file_size,sizeof(file_size));
            read(client_socket, file_size, MAXLINE);
            send(client_socket, "inRemote", strlen("inRemote"), 0);
            printf("-- Sync Status: unsynced.\n");
            char lockMessage[MAXLINE];
            bzero(lockMessage,sizeof(lockMessage));
            read(client_socket,lockMessage,MAXLINE);
            if(strcmp(lockMessage,"yes")==0){
              printf("-- Lock Status: locked.\n");
            }
            else{
              printf("-- Lock Status: unlocked.\n");
            }
            
        }
        else{
          printf("File [%s] could not be found in remote directory or local directory.\n", file_name);
        }
        
    }
    return 0;
}



int main(int argc, char **argv){
    int client_socket;
    struct sockaddr_in serv_addr;
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (client_socket < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // The server IP address should be supplied as an argument when running the application.
    int addr_status = inet_pton(AF_INET, argv[2], &serv_addr.sin_addr);
    if (addr_status <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    int connect_status = connect(client_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (connect_status < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    printf("Welcome to ICS53 Online Cloud Storage.\n");
    ///////////// main process //////////////
    freopen(argv[1], "r", stdin);
    char buf[MAXLINE];
    //printf("connected: %d\n", client_socket);
    while(1){
        bzero(buf, sizeof(buf));
        char* tokens[80];
        fgets(buf, 80, stdin);
        if(buf[strlen(buf)-1] == '\n'){
          buf[strlen(buf)-1] = '\0';
        }
        char* copy = NULL;
        copy = (char *) malloc( strlen(buf) + 1 ); 
        strcpy( copy, buf );

        printf("> %s\n", copy);
        if(strcmp(buf, "\n") == 0){
            continue;
        }
        if(strcmp(buf, "") == 0){
            continue;
        }
        inputParser(copy, tokens);

        //printf("token1: %s, token2: %s--\n", tokens[0], tokens[1]);
        if(strcmp(tokens[0], "quit") == 0){
          write(client_socket, "quit", strlen("quit"));
          close(client_socket);
          exit(0);
        }
        else if(strcmp(tokens[0], "pause") == 0){
          int time = atoi(tokens[1]);
          //printf("This client is pauseing for %d second\n", time);
          sleep(time);
        }
        else if(strcmp(tokens[0], "append") == 0){
          write(client_socket, "append", strlen("append"));
          bzero(buf, sizeof(buf));
          recv(client_socket, buf, MAXLINE, 0);
          //printf("buf: %s\n", buf);
          bzero(buf, sizeof(buf));
          write(client_socket, tokens[1], strlen(tokens[1]));
          char temp[MAXLINE];
          bzero(temp, sizeof(temp));
          recv(client_socket, temp, MAXLINE, 0);
          //printf("1: %s\n", temp);
          if(strcmp(temp, "yes") == 0){
            send(client_socket, "intoappendmode", strlen("intoappendmode"), 0);
            char message[MAXLINE];
            bzero(message, sizeof(message));
            recv(client_socket, message, MAXLINE, 0);
            //printf("2: %s\n", message);
            if(strcmp(message,"no")==0){
              printf("File [%s] is currently locked by another user.\n",tokens[1]);
              continue;;
            }
            int indicator = 0;
            while(indicator == 0){
              bzero(buf, sizeof(buf));
              fgets(buf, MAXLINE, stdin);
              if(buf[strlen(buf)-1] == '\n'){
                buf[strlen(buf)-1] = '\0';
              }
              indicator = append_mode(client_socket, buf);
              bzero(buf, sizeof(buf));
            }
          }
          else{
              printf("File [%s] could not be found in remote directory.\n", tokens[1]);
          }
        }
        else if(strcmp(tokens[0], "upload") == 0){
          char path[1024];
          char destination_path[MAXLINE] = "/Local\ Directory/";
          strcat(destination_path, tokens[1]);
          getcwd(path, MAXLINE);
          strcat(path, destination_path);
          //printf("%s\n", path);
          if (access(path, F_OK) == 0) {
              //printf("file exit\n");
              write(client_socket, "upload", strlen("upload"));
              
              char temp2[MAXLINE];
              bzero(temp2,sizeof(temp2));
              recv(client_socket, temp2, MAXLINE, 0);
              //printf("temp2: %s\n", temp2);

              write(client_socket, tokens[1], strlen(tokens[1]));
              bzero(buf, sizeof(buf));
              
              char message[MAXLINE];
              bzero(message,sizeof(message));
              read(client_socket, message, MAXLINE);
              //printf("return message: %s",message);
              if(strcmp(message,"no")==0){
                printf("File [%s] is currently locked by another user.\n",tokens[1]);
              }
              else{
                sending(client_socket, path);
              }
          } 
          else {
              printf("File [%s] could not be found in local directory.\n", tokens[1]);
          }
        }
        else if(strcmp(tokens[0], "download") == 0){
          send(client_socket, "download", strlen("download"), 0);

          bzero(buf, sizeof(buf));
          recv(client_socket, buf, MAXLINE, 0);
          bzero(buf, sizeof(buf));
          //printf("%s\n", tokens[1]);
          send(client_socket, tokens[1], strlen(tokens[1]), 0);
          
          //printf("----------------------------------------------------------------\n");
          
          receiving(client_socket, tokens[1]);
        }
        else if(strcmp(tokens[0], "delete") == 0){
          write(client_socket, "delete", strlen("delete"));
          bzero(buf, sizeof(buf));
          recv(client_socket, buf, MAXLINE, 0);
          bzero(buf, sizeof(buf));

          write(client_socket, tokens[1], strlen(tokens[1]));
          char message[MAXLINE];
          bzero(message, sizeof(message));
          read(client_socket, message, MAXLINE);
          //printf("%s\n", message);
          if(strcmp(message, "yes") == 0){
              send(client_socket, "deleting", strlen("deleting"), 0);
              char message[MAXLINE];
              bzero(message,sizeof(message));
              read(client_socket, message, MAXLINE);
              //printf("return message: %s",message);
              if(strcmp(message,"no")==0){
                printf("File [%s] is currently locked by another user.\n",tokens[1]);
                continue;;
              }
              printf("File deleted successfully.\n");
          }
          else{
              printf("File [%s] could not be found in remote directory.\n", tokens[1]);
          }
        }
        else if(strcmp(tokens[0], "syncheck") == 0){
          // printf("0\n");
          write(client_socket, "syncheck", strlen("syncheck"));
          bzero(buf, sizeof(buf));
          recv(client_socket, buf, MAXLINE, 0);
          bzero(buf, sizeof(buf));
          // printf("1\n");
          write(client_socket, tokens[1], strlen(tokens[1]));
          
          syncheck(client_socket, tokens[1]);
        }
        else{
          printf("Command [%s] is not recognized.\n",tokens[0]);
            continue;
        }
    }
}