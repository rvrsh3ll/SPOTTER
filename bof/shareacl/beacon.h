/*
 * Minimal Beacon API declarations for Cobalt Strike BOF compilation.
 *
 * This stub contains only the functions and types required by shareacl.c.
 * For the full Beacon API, see the Cobalt Strike "User-Defined Reflective DLLs
 * and Beacon Object Files" documentation.
 */
#ifndef _BEACON_H_
#define _BEACON_H_

/* Beacon output types */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* Argument parser state */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* Argument parsing API */
void   BeaconDataParse(datap *parser, char *buffer, int size);
char * BeaconDataExtract(datap *parser, int *size);
int    BeaconDataInt(datap *parser);
short  BeaconDataShort(datap *parser);

/* Console output API */
void BeaconPrintf(int type, char *fmt, ...);

#endif /* _BEACON_H_ */
