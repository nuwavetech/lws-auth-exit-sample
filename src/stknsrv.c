//
//  Auth Exits sample token server for LightWave Server.
//
#pragma nolist

#include <cextdecs>
#include <tal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <strings.h>

#include "zsysc"

// Helper macros for syntax check under smart editors.
#if defined(__TANDEM)
#define OMIT /**/
#else
int omitParam;
#define OMIT omitParam
#endif
#pragma list

#define SET_BIT(num, pos) ((num) |= (1 << (15 - (pos))))

// LWAE.H is a header produced from the DDL source LWAEDDL included with
// LightWave Server. It must be available for this program to compile.
#include "lwae.h"

// Standard arguments for request handler functions.
#define STKNSRV_FUNCTION_ARGS                                                  \
  void *buffer, long long length, long long tag,                               \
      zsys_ddl_recvinformation2_def *info

//  Static data.

static short tmpFileNumber = -1;
static short receiveFileNumber = -1;
static long localNodeNumber = 0;
static int openCount = 0;
static int ignoreClose = 0;
static int autoRestart = 0;

static char processName[32];

//  Local functions.
static void logMessage(const char* format, ...);
static char* parseUserPass(const char* input);
static char* trimWhitespace(char* str);

// In case strdup not available.
#if defined(strdup)
#define utilStrdup strdup
#else
char* utilStrdup(const char* src);
#endif

//  Request Handlers.

static void handleInfoTknSetRequest(STKNSRV_FUNCTION_ARGS);
static void handleVerifyTknSetRequest(STKNSRV_FUNCTION_ARGS);

//  The dispatch table.
typedef struct _dispatchEntry {
  short msgCode;
  void (*functionRef)(STKNSRV_FUNCTION_ARGS);
} dispatchEntry;

dispatchEntry _dispatchTable[] = {
    {lw_ae_rq_info_tkn_set_v1, handleInfoTknSetRequest},
    {lw_ae_rq_verify_tkn_set_v1, handleVerifyTknSetRequest},

    {-1, NULL}};

int main(int argc, char** argv) {
  short length;
  char* receiveBuffer;
  long long ioTag;
  int ioLength;
  short fileNumber;
  short ioResult;
  zsys_ddl_recvinformation2_def receiveInfo;
  short* msgCode;
  char* ioBuffer;
  int receivePending;
  int timeToStop;
  int didReply = 0;
  char temp[256];
  int i;

#define IO_SIZE 2097152 /* Max I/O size - 2MB */

  //  Scan arguments (no error checking ... all args assumed lower case).
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "-ignoreclose") == 0)
      ignoreClose = -1;

    if (strcmp(argv[i], "-autorestart") == 0)
      autoRestart = -1;
  }

  //  printf("DEBUG: Ignore close is %d\n", ignoreClose);
  //  printf("DEBUG: Autorestart is %d\n", autoRestart);

  //  Get our process name.

  {
    short len;
    short processHandle[10];

    PROCESSHANDLE_GETMINE_(processHandle);
    PROCESSHANDLE_DECOMPOSE_(processHandle, OMIT, OMIT, OMIT, OMIT, OMIT, OMIT,
                             processName, sizeof(processName), &len);

    processName[len] = 0;
  }

  logMessage("SERVER Token Server starting");

  //  Open $Receive.
  FILE_OPEN_("$RECEIVE", 8, &receiveFileNumber, OMIT, OMIT, 1, 1);

  //  Open the TFILE to allow multithreaded transactions.
  FILE_OPEN_("$TMP", 4, &tmpFileNumber, OMIT, OMIT, 100);

  //  Increase the message system limits. This allows us to have up to 4096
  //  message stacked up in our $RECEIVE queue.
  CONTROLMESSAGESYSTEM(1, 4095);

  //  Get the local node number.
  NODENAME_TO_NODENUMBER_(OMIT, 0, &localNodeNumber);

  //  Allocate the buffer.
  receiveBuffer = malloc(IO_SIZE);

  //  Start the $RECEIVE loop.
  timeToStop = 0;
  receivePending = 0;
  SIGNALTIMEOUT(1); // prime the timer.

  while (!timeToStop) {
    //  If we don't have a read outstanding on $RECEIVE then issue one now.
    if (!receivePending) {
      READUPDATEXL(receiveFileNumber, receiveBuffer, IO_SIZE);
      receivePending = -1;
    }

    //  Now wait for completion on any file.
    fileNumber = -1;
    ioTag = 0;

    ioResult = AWAITIOXL(&fileNumber, (long*)&ioBuffer, &ioLength, &ioTag);
    FILE_GETINFO_(fileNumber, &ioResult);

    //  If the IO completed on $RECEIVE then get receiveinfo and clear the
    //  receivePending and didReply.
    if (fileNumber == 0) {
      receivePending = 0;
      didReply = 0;
      FILE_GETRECEIVEINFOL_((short*)&receiveInfo);
    }

    //  If this is a TFILE IO then ignore it.
    if (fileNumber == tmpFileNumber) {
      continue;
    }
    //
    //  Handle system messages here. If the IO completed on $RECEIVE and the
    //  ioResult is 6 then it's a system message.
    //
    if (fileNumber == 0 && ioResult == 6) {
      msgCode = (short*)&receiveBuffer[0];

      //      printf("message %d, max reply %d\n", (int) *msgCode,
      //      receiveInfo.z_maxreplycount);

      switch (*msgCode) {
      case ZSYS_VAL_SMSG_TIMESIGNAL:

        SIGNALTIMEOUT(1500); // hundreths of a second.
        break;

      case ZSYS_VAL_SMSG_OPEN:

        //  Get the name of the process that opened us, in case we need it.
        PROCESSHANDLE_TO_FILENAME_((short*)&receiveInfo.z_sender, temp,
                                   sizeof(temp), &length, 1);
        temp[length] = 0; // Null terminate the process file name.

        openCount++; // increment the count of processes that have us open.

        break;

      case ZSYS_VAL_SMSG_CLOSE:

        openCount--;

        //  Get the name of the process that closed us.
        PROCESSHANDLE_TO_FILENAME_((short*)&receiveInfo.z_sender, temp,
                                   sizeof(temp), &length, 1);
        temp[length] = 0; // Null terminate the process file name.

        //  If we're a pathway server and our openCount is zero then by rule we
        //  shut down.
        if (ignoreClose == 0 && openCount == 0) {
          timeToStop = -1;
        }

        break;

      case ZSYS_VAL_SMSG_CONTROL:
        //  Some process sent a CONTROL message.
        break;

      default:
        //  Ignore everything else.
        break;
      }

      //  If we haven't replied yet then just send an empty reply.
      if (!didReply)
        REPLYXL(OMIT, OMIT, OMIT, receiveInfo.z_messagetag);

      continue;
    }

    //  If something else came in on $RECEIVE then it's an application message.
    if (fileNumber == 0) {

      //  If the message is empty then reply with an empty message.
      if (ioLength == 0) {
        REPLYXL(OMIT, OMIT, OMIT, receiveInfo.z_messagetag);
        continue;
      }

      msgCode = (short*)&receiveBuffer[0];

      //      printf("message %d, max reply %d\n", (int) *msgCode,
      //      receiveInfo.z_maxreplycount);

      //  Dispatch the message.
      {
        int i;
        int dispatched = 0;

        for (i = 0; i < sizeof(_dispatchTable) / sizeof(dispatchEntry); i++) {
          if (_dispatchTable[i].msgCode == *msgCode) {
            dispatched = -1;
            (*_dispatchTable[i].functionRef)(receiveBuffer, ioLength, ioTag,
                                             &receiveInfo);
            break;
          }
        }

        //  If the message was not recognized then return an error.
        if (!dispatched) {
          REPLYXL(OMIT, OMIT, OMIT, receiveInfo.z_messagetag, 2);
        }
      }

      continue;
    }
  }

  if (autoRestart)
    return -1;

  return 0;
}

/// @brief Process "Info Token Set" requests.
/// @param buffer The received message buffer.
/// @param length The message buffer length.
/// @param tag The message IO tag.
/// @param info A reference to a zsys_ddl_receiveinformation_def structure for
/// the msg.
static void handleInfoTknSetRequest(STKNSRV_FUNCTION_ARGS) {
  short result = 0;
  lw_ae_info_tkn_set_v1_rq_def* rq = buffer;
  lw_ae_info_tkn_set_v1_rp_def rp;
  lw_ae_token_error_rp_def error_rp;

  // NOTE: This would be where the token set info would be retrieved for sending
  // back to LightWave Server.

  // Simulate token set info based on the token set name received in the
  // request. Other criteria could be used for determining the token set
  // returned.

  memset(&rp, 0, sizeof(rp));
  rp.header.rp_code = lw_ae_rp_success;
  memcpy((char*)&rp.tkn_set_name, rq->tkn_set_name, rq->tkn_set_name_len);
  rp.tkn_set_name_len = rq->tkn_set_name_len;

  if (rq->tkn_set_name_len <= 0 || // Default is token set 1
      strncmp(rq->tkn_set_name, "test-token-set-1", rq->tkn_set_name_len) ==
          0) {
    rp.tkn_set_ttl = 60; // Seconds for LightWave Server to retain in cache
    rp.tkn_count = 1;

    rp.tkn_set[0].tkn_type = lw_ae_tkn_type_header;
    rp.tkn_set[0].base64_decode = 1;
    strncpy(rp.tkn_set[0].tkn_format, "Bearer %s",
            sizeof(rp.tkn_set[0].tkn_format));
    rp.tkn_set[0].tkn_format_len = (int)strlen(rp.tkn_set[0].tkn_format);
    strncpy(rp.tkn_set[0].tkn_name, "Authorization",
            sizeof(rp.tkn_set[0].tkn_name));
    rp.tkn_set[0].tkn_name_len = (int)strlen(rp.tkn_set[0].tkn_name);

  } else if (strncmp(rq->tkn_set_name, "test-token-set-2",
                     rq->tkn_set_name_len) == 0) {
    rp.tkn_set_ttl = 30;
    rp.tkn_count = 2;

    rp.tkn_set[0].tkn_type = lw_ae_tkn_type_header;
    rp.tkn_set[0].base64_decode = 0;
    strncpy(rp.tkn_set[0].tkn_format, "Bearer %s",
            sizeof(rp.tkn_set[0].tkn_format));
    rp.tkn_set[0].tkn_format_len = (int)strlen(rp.tkn_set[0].tkn_format);
    strncpy(rp.tkn_set[0].tkn_name, "Authorization",
            sizeof(rp.tkn_set[0].tkn_name));
    rp.tkn_set[0].tkn_name_len = (int)strlen(rp.tkn_set[0].tkn_name);

    rp.tkn_set[1].tkn_type = lw_ae_tkn_type_param;
    rp.tkn_set[1].base64_decode = 1;
    strncpy(rp.tkn_set[1].tkn_format, "param-token-2-%s",
            sizeof(rp.tkn_set[1].tkn_format));
    rp.tkn_set[1].tkn_format_len = (int)strlen(rp.tkn_set[1].tkn_format);
    strncpy(rp.tkn_set[1].tkn_name, "testae-param-token",
            sizeof(rp.tkn_set[1].tkn_name));
    rp.tkn_set[1].tkn_name_len = (int)strlen(rp.tkn_set[1].tkn_name);

  } else if (strncmp(rq->tkn_set_name, "test-token-set-3",
                     rq->tkn_set_name_len) == 0) {
    rp.tkn_set_ttl = 90;
    rp.tkn_count = 1;

    rp.tkn_set[0].tkn_type = lw_ae_tkn_type_param;
    rp.tkn_set[0].base64_decode = 0;
    strncpy(rp.tkn_set[0].tkn_format, "param-token-3-%s",
            sizeof(rp.tkn_set[0].tkn_format));
    rp.tkn_set[0].tkn_format_len = (int)strlen(rp.tkn_set[0].tkn_format);
    strncpy(rp.tkn_set[0].tkn_name, "testae-param-token",
            sizeof(rp.tkn_set[0].tkn_name));
    rp.tkn_set[0].tkn_name_len = (int)strlen(rp.tkn_set[0].tkn_name);

  } else if (strncmp(rq->tkn_set_name,
                     "test-token-set-g", // Guardian User ID/password Token
                     rq->tkn_set_name_len) == 0) {
    rp.tkn_set_ttl = 90; // Seconds for LightWave Server to retain in cache
    rp.tkn_count = 1;

    rp.tkn_set[0].tkn_type = lw_ae_tkn_type_header;
    rp.tkn_set[0].base64_decode = 1;
    strncpy(rp.tkn_set[0].tkn_format, "%s", sizeof(rp.tkn_set[0].tkn_format));
    rp.tkn_set[0].tkn_format_len = (int)strlen(rp.tkn_set[0].tkn_format);
    strncpy(rp.tkn_set[0].tkn_name, "NSK-Authorization",
            sizeof(rp.tkn_set[0].tkn_name));
    rp.tkn_set[0].tkn_name_len = (int)strlen(rp.tkn_set[0].tkn_name);

  } else {
    memset(&error_rp, 0, sizeof(error_rp));
    error_rp.header.rp_code = lw_ae_rp_error;
    error_rp.error_code = lw_ae_rp_unknown_tkn_set_name;
    error_rp.error_subcode = rq->header.rq_code;
    error_rp.error_message_len = snprintf(
        error_rp.error_message, sizeof(error_rp.error_message),
        "info error response: unknown token set name '%s'", rq->tkn_set_name);
    buffer = &error_rp;
    length = offsetof(lw_ae_token_error_rp_def, error_message) +
             error_rp.error_message_len;
    goto Exit;
  }

  buffer = &rp;
  length = offsetof(lw_ae_info_tkn_set_v1_rp_def, tkn_set) +
           (rp.tkn_count * sizeof(rp.tkn_set[0]));

Exit:

  REPLYXL(buffer, (int)length, OMIT, info->z_messagetag, result);
}

/// @brief Process "Verify Token Set" requests.
/// @param buffer The received message buffer.
/// @param length The message buffer length.
/// @param tag The message IO tag.
/// @param info A reference to a zsys_ddl_receiveinformation_def structure for
/// the msg.
static void handleVerifyTknSetRequest(STKNSRV_FUNCTION_ARGS) {
  short result = 0;
  lw_ae_verify_tkn_set_v1_rq_def* rq = buffer;
  lw_ae_verify_tkn_set_v1_rp_def rp;

  // Initialize the reply buffer for success.
  memset(&rp, 0, sizeof(rp));
  rp.header.rp_code = lw_ae_rp_success;
  memcpy((char*)&rp.tkn_set_name, rq->tkn_set_name, rq->tkn_set_name_len);
  rp.tkn_set_name_len = rq->tkn_set_name_len;

  // NOTE: This would be the point where the token values would be verified, or
  // the token server makes a "callout" to a token provider for verification.

  if (strncmp(rq->tkn_set_name, "test-token-set-g", rq->tkn_set_name_len) ==
      0) {
    //*******************************
    //*******************************
    // This token set name is just a sample, defined as having one token with
    // the name "NSK-Authorization". If this token set were defined with
    // multiple tokens, each would have to be indivisually verified. For the
    // sample, things are kept simple.
    //*******************************
    //*******************************

    // Verify a Guardian User and password received as a token. The token value
    // sent in the request is formatted as "userid:password" (the same as in
    // basic HTTP authentication). However, USER_AUTHENTICATE_ requires the user
    // ID and password formatted as "userid, password". We do NOT request logon.
    char* inputText;
    short options = 0;
    short statusFlags;
    short status;
    short rc;

    // The first token in this token set is defined as the user ID and password.
    inputText = parseUserPass(rq->tkn_set[0].tkn_value);
    if (inputText == NULL) {
      rp.header.rp_code = lw_ae_rp_error;
    } else {
      SET_BIT(options, 8); // Not in dialog mode; uid/pwd in inputText

      rc = USER_AUTHENTICATE_(inputText, (short)strlen(inputText), options,
                              OMIT, &status, &statusFlags);
      if (rc != 0) {

        // Analyze the error if needed.

        // NOTE: A lw_ae_token_error_rp_def reply is NOT used here because this
        // was not a processing error, but a data content error.
        rp.header.rp_code = lw_ae_rp_error;
      }

      free(inputText);
    }
  } else {
    // Do something for other token sets?
  }

  // Return the result of the verification.

  rp.tkn_set_ttl = 45; // seconds for LightWave Server to retain in cache

  buffer = &rp;
  length = sizeof(lw_ae_verify_tkn_set_v1_rp_def);

  REPLYXL(buffer, (int)length, OMIT, info->z_messagetag, result);
}

/// @brief Logs a message to a file called ZZTSLOG. If the file does not exist,
/// it is created.
/// @param format The "printf-style" format string for the message.
/// @param  Additional parameters corresponding to the format specifier.
static void logMessage(const char* format, ...) {
  va_list list;
  char tmp[1024];
  char* p;
  char fileName[32];
  short filenum;
  short len;
  short rc;

  //  Open/create the output file. */
  strcpy(fileName, "ZZTSLOG");
  rc = FILE_OPEN_(fileName, (short)strlen(fileName), &filenum, 2);

  if (rc == 11) {
    len = (short)strlen(fileName);
    rc = FILE_CREATE_(fileName, sizeof(fileName), &len, 0, 500, 500, 750, 2, 0,
                      1024);
    rc = FILE_OPEN_(fileName, (short)strlen(fileName), &filenum, 2);
  }

  if (rc == 0) {
    time_t now;
    struct tm* tm;

    now = time(NULL);
    tm = localtime(&now);

    p = tmp;
    p += sprintf(p, "%s %02d-%02d-%04d %02d:%02d:%02d : ", processName,
                 tm->tm_mon + 1, tm->tm_mday, tm->tm_year + 1900, tm->tm_hour,
                 tm->tm_min, tm->tm_sec);

    va_start(list, format);
    p += vsprintf(p, format, list);
    va_end(list);

    WRITEX(filenum, tmp, (unsigned short)(p - tmp));
    FILE_CLOSE_(filenum);
  }
}

// Function to parse "userID:password" and return "userID, password"
// Caller must free returned string.
static char* parseUserPass(const char* input) {
  size_t output_size;
  char* password;
  char* userID;
  char* output;
  char* copy;

  if (input == NULL)
    return NULL;

  copy = utilStrdup(input); // Make a mutable copy of the input
  if (copy == NULL)
    return NULL;

  userID = copy;
  password = strchr(copy, ':');
  if (password == NULL) {
    free(copy);
    return NULL; // Invalid format (no colon found)
  }

  *password = '\0'; // Split into two strings
  password++;       // Move past the colon

  userID = trimWhitespace(userID);
  password = trimWhitespace(password);

  // Allocate output string with space for "userID, password" (including null
  // terminator)
  output_size = strlen(userID) + strlen(password) + 3;
  output = malloc(output_size);
  if (output == NULL) {
    free(copy);
    return NULL;
  }

  snprintf(output, output_size, "%s, %s", userID, password);
  free(copy);

  return output;
}

// Function to trim leading and trailing whitespace
static char* trimWhitespace(char* str) {
  char* end;

  // Trim leading space
  while (isspace((unsigned char)*str))
    str++;

  // If all spaces, return an empty string
  if (*str == 0)
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;

  // Write new null terminator
  *(end + 1) = '\0';

  return str;
}

// In case strdup not available.
#if !defined(strdup)
static char* utilStrdup(const char* src) {
  size_t len;
  char* dst;

  len = strlen(src) + 1;
  dst = malloc(len);
  if (dst == NULL) {
    return NULL;
  }
  memcpy(dst, src, len);

  return dst;
}
#endif

//  End of file.
