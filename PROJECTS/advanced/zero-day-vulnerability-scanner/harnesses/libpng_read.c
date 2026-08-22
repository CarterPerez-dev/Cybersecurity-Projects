// ©AngelaMos | 2026
// libpng_read.c

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "png.h"

#define LISDEX_SIG_BYTES 8
#define LISDEX_MAX_ALLOC (64u * 1024u * 1024u)
#define LISDEX_MAX_PIXELS (1u << 24)

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} lisdex_buffer;

static void lisdex_read(png_structp png, png_bytep out, size_t count)
{
    lisdex_buffer *buf = (lisdex_buffer *)png_get_io_ptr(png);

    if (buf == NULL || buf->offset > buf->size ||
        count > buf->size - buf->offset) {
        png_error(png, "lisdex: read past end of buffer");
        return;
    }

    memcpy(out, buf->data + buf->offset, count);
    buf->offset += count;
}

static png_voidp lisdex_malloc(png_structp png, png_alloc_size_t size)
{
    (void)png;

    if (size == 0 || size > LISDEX_MAX_ALLOC) {
        return NULL;
    }

    return malloc((size_t)size);
}

static void lisdex_free(png_structp png, png_voidp ptr)
{
    (void)png;
    free(ptr);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    png_structp png = NULL;
    png_infop info = NULL;
    png_infop end_info = NULL;
    volatile png_bytep row = NULL;
    lisdex_buffer buf;
    png_uint_32 width = 0;
    png_uint_32 height = 0;
    png_uint_32 y = 0;
    int depth = 0;
    int color_type = 0;
    int interlace = 0;
    int passes = 1;
    int pass = 0;
    size_t rowbytes = 0;

    if (size < LISDEX_SIG_BYTES) {
        return 0;
    }

    if (png_sig_cmp((png_const_bytep)data, 0, LISDEX_SIG_BYTES) != 0) {
        return 0;
    }

    png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL,
                                   NULL, lisdex_malloc, lisdex_free);
    if (png == NULL) {
        return 0;
    }

    info = png_create_info_struct(png);
    end_info = png_create_info_struct(png);
    if (info == NULL || end_info == NULL) {
        png_destroy_read_struct(&png, &info, &end_info);
        return 0;
    }

    if (setjmp(png_jmpbuf(png))) {
        free((png_bytep)row);
        png_destroy_read_struct(&png, &info, &end_info);
        return 0;
    }

    buf.data = data;
    buf.size = size;
    buf.offset = 0;

    png_set_read_fn(png, &buf, lisdex_read);
    png_set_crc_action(png, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
    png_set_option(png, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

    png_read_info(png, info);

    if (png_get_IHDR(png, info, &width, &height, &depth, &color_type,
                     &interlace, NULL, NULL) == 0) {
        png_destroy_read_struct(&png, &info, &end_info);
        return 0;
    }

    if (width == 0 || height > LISDEX_MAX_PIXELS / width) {
        png_destroy_read_struct(&png, &info, &end_info);
        return 0;
    }

    passes = png_set_interlace_handling(png);
    png_read_update_info(png, info);

    rowbytes = png_get_rowbytes(png, info);
    row = (png_bytep)malloc(rowbytes > 0 ? rowbytes : 1);
    if (row == NULL) {
        png_destroy_read_struct(&png, &info, &end_info);
        return 0;
    }

    for (pass = 0; pass < passes; pass++) {
        for (y = 0; y < height; y++) {
            png_read_row(png, (png_bytep)row, NULL);
        }
    }

    free((png_bytep)row);
    row = NULL;

    png_read_end(png, end_info);
    png_destroy_read_struct(&png, &info, &end_info);

    return 0;
}
