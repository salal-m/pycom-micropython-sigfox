#ifndef __BSDIFF_API__

#define __BSDIFF_API__

//int create_delta(char *basis_fname, char *target_fname, char *patch_fname);

off_t offtin(u_char *buf);

int patch_binary(char *basis_name, char *patch_fname, int *out_size, unsigned char *out_buffer);

#endif