#ifndef STKNSRV_H_INCLUDED_
#define STKNSRV_H_INCLUDED_ 1
/**
 * This file contains declarations for the test server.
 */

/* Helper macros for compiling under Eclipse. Allows for parameter omission on both platforms. */
#if defined(__TANDEM)
#define OMIT /**/
#else
int omitParam;
#define OMIT  omitParam
#endif

/* Standard arguments for test functions. */
#define STKNSRV_FUNCTION_ARGS void* buffer, long long length, long long tag, zsys_ddl_recvinformation2_def* info

/** End of file */
#endif
