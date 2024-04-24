/*
 * jp2.cpp
 *
 *  Created on: Sep 11, 2018
 *      Author: echo
 */

#include "JP2.h"
#include "Ptypes.h"
#include <vector>
#include <opencv2/opencv.hpp>

#if USE_OPENJPEG

#include "openjpeg.h"

#endif

//#define LOG_TAG "PassportReaderCPP-JP2"
//#define LOG_DEBUG
//#define OOXX_JP2_DEBUG_LOG 1
//#include "internalLogging.h"

#if USE_OPENJPEG

#ifdef DEBUG
static void info_callback(const char *msg, void *client_data)
{
    //std::cout << msg << std::endl;
}

static void warning_callback(const char *msg, void *client_data)
{
    //std::cout << msg << std::endl;
}

static void error_callback(const char *msg, void *client_data)
{
    //std::cout << msg << std::endl;
}
#endif

struct opj_stream_memory {
    char *input;
    OPJ_SIZE_T input_len;
    OPJ_SIZE_T read_offset;
};

static void opj_stream_free_memory(void *p_user_data) {
    if (p_user_data) {
        struct opj_stream_memory *posm = (struct opj_stream_memory *) p_user_data;
        if (posm->input) {
            free(posm->input);
            posm->input = NULL;
        }
        free(p_user_data);
    }
}

static OPJ_SIZE_T opj_stream_read_memory(void *p_buffer, OPJ_SIZE_T p_nb_bytes,
                                         void *p_user_data) {
    struct opj_stream_memory *osm = (struct opj_stream_memory *) p_user_data;
    OPJ_SIZE_T left = osm->input_len - osm->read_offset;
    OPJ_SIZE_T cpySize = MIN(left, p_nb_bytes);
    if (p_buffer && cpySize) {
        memcpy(p_buffer, osm->input + osm->read_offset, cpySize);
        osm->read_offset += cpySize;
        return cpySize;
    }
    return (OPJ_SIZE_T) -1;
}

static opj_stream_t *opj_stream_create_memory_stream(char *buf, size_t size) {
    opj_stream_t *s = NULL;
    struct opj_stream_memory *posm = NULL;

    if (!buf || !size) {
        return NULL;
    }

    posm = (struct opj_stream_memory *) calloc(1, sizeof(struct opj_stream_memory));
    if (!posm) {
        return NULL;
    }
    posm->input = (char *) calloc(size, 1);
    if (!posm->input) {
        opj_stream_free_memory(posm);
        return NULL;
    }
    memcpy(posm->input, buf, size);
    posm->input_len = size;
    posm->read_offset = 0;

    s = opj_stream_default_create(OPJ_TRUE);
    if (!s) {
        opj_stream_free_memory(posm);
        return NULL;
    }

    opj_stream_set_user_data(s, posm, opj_stream_free_memory);

    opj_stream_set_user_data_length(s, size);

    opj_stream_set_read_function(s, opj_stream_read_memory);

    return s;
}

int imagetobmp(opj_image_t *image, const char *outfile) {
    int w, h;
    int i, pad;
    FILE *fdest = NULL;
    int adjustR, adjustG, adjustB;

    if (image->comps[0].prec < 8) {
        fprintf(stderr, "imagetobmp: Unsupported precision: %d\n",
                image->comps[0].prec);
        return 1;
    }
    if (image->numcomps >= 3 && image->comps[0].dx == image->comps[1].dx
        && image->comps[1].dx == image->comps[2].dx
        && image->comps[0].dy == image->comps[1].dy
        && image->comps[1].dy == image->comps[2].dy
        && image->comps[0].prec == image->comps[1].prec
        && image->comps[1].prec == image->comps[2].prec
        && image->comps[0].sgnd == image->comps[1].sgnd
        && image->comps[1].sgnd == image->comps[2].sgnd) {

        /* -->> -->> -->> -->>
        24 bits color
        <<-- <<-- <<-- <<-- */

        fdest = fopen(outfile, "wb");
        if (!fdest) {
            fprintf(stderr, "ERROR -> failed to open %s for writing\n", outfile);
            return 1;
        }

        w = (int) image->comps[0].w;
        h = (int) image->comps[0].h;

        fprintf(fdest, "BM");

        /* FILE HEADER */
        /* ------------- */
        fprintf(fdest, "%c%c%c%c",
                (OPJ_UINT8) (h * w * 3 + 3 * h * (w % 2) + 54) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2) + 54) >> 8) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2) + 54) >> 16) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2) + 54) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (54) & 0xff, ((54) >> 8) & 0xff, ((54) >> 16) & 0xff,
                ((54) >> 24) & 0xff);

        /* INFO HEADER   */
        /* ------------- */
        fprintf(fdest, "%c%c%c%c", (40) & 0xff, ((40) >> 8) & 0xff, ((40) >> 16) & 0xff,
                ((40) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) ((w) & 0xff),
                (OPJ_UINT8) ((w) >> 8) & 0xff,
                (OPJ_UINT8) ((w) >> 16) & 0xff,
                (OPJ_UINT8) ((w) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) ((h) & 0xff),
                (OPJ_UINT8) ((h) >> 8) & 0xff,
                (OPJ_UINT8) ((h) >> 16) & 0xff,
                (OPJ_UINT8) ((h) >> 24) & 0xff);
        fprintf(fdest, "%c%c", (1) & 0xff, ((1) >> 8) & 0xff);
        fprintf(fdest, "%c%c", (24) & 0xff, ((24) >> 8) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) (3 * h * w + 3 * h * (w % 2)) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2)) >> 8) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2)) >> 16) & 0xff,
                (OPJ_UINT8) ((h * w * 3 + 3 * h * (w % 2)) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
                ((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
                ((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);

        if (image->comps[0].prec > 8) {
            adjustR = (int) image->comps[0].prec - 8;
           
        } else {
            adjustR = 0;
        }
        if (image->comps[1].prec > 8) {
            adjustG = (int) image->comps[1].prec - 8;
            
        } else {
            adjustG = 0;
        }
        if (image->comps[2].prec > 8) {
            adjustB = (int) image->comps[2].prec - 8;
           
        } else {
            adjustB = 0;
        }

        for (i = 0; i < w * h; i++) {
            OPJ_UINT8 rc, gc, bc;
            int r, g, b;

            r = image->comps[0].data[w * h - ((i) / (w) + 1) * w + (i) % (w)];
            r += (image->comps[0].sgnd ? 1 << (image->comps[0].prec - 1) : 0);
            if (adjustR > 0) {
                r = ((r >> adjustR) + ((r >> (adjustR - 1)) % 2));
            }
            if (r > 255) {
                r = 255;
            } else if (r < 0) {
                r = 0;
            }
            rc = (OPJ_UINT8) r;

            g = image->comps[1].data[w * h - ((i) / (w) + 1) * w + (i) % (w)];
            g += (image->comps[1].sgnd ? 1 << (image->comps[1].prec - 1) : 0);
            if (adjustG > 0) {
                g = ((g >> adjustG) + ((g >> (adjustG - 1)) % 2));
            }
            if (g > 255) {
                g = 255;
            } else if (g < 0) {
                g = 0;
            }
            gc = (OPJ_UINT8) g;

            b = image->comps[2].data[w * h - ((i) / (w) + 1) * w + (i) % (w)];
            b += (image->comps[2].sgnd ? 1 << (image->comps[2].prec - 1) : 0);
            if (adjustB > 0) {
                b = ((b >> adjustB) + ((b >> (adjustB - 1)) % 2));
            }
            if (b > 255) {
                b = 255;
            } else if (b < 0) {
                b = 0;
            }
            bc = (OPJ_UINT8) b;

            fprintf(fdest, "%c%c%c", bc, gc, rc);

            if ((i + 1) % w == 0) {
                for (pad = ((3 * w) % 4) ? (4 - (3 * w) % 4) : 0; pad > 0; pad--) { /* ADD */
                    fprintf(fdest, "%c", 0);
                }
            }
        }
        fclose(fdest);
    } else {            /* Gray-scale */

        /* -->> -->> -->> -->>
        8 bits non code (Gray scale)
        <<-- <<-- <<-- <<-- */

        fdest = fopen(outfile, "wb");
        if (!fdest) {
            fprintf(stderr, "ERROR -> failed to open %s for writing\n", outfile);
            return 1;
        }
        if (image->numcomps > 1) {
            fprintf(stderr, "imagetobmp: only first component of %d is used.\n",
                    image->numcomps);
        }
        w = (int) image->comps[0].w;
        h = (int) image->comps[0].h;

        fprintf(fdest, "BM");

        /* FILE HEADER */
        /* ------------- */
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) (h * w + 54 + 1024 + h * (w % 2)) & 0xff,
                (OPJ_UINT8) ((h * w + 54 + 1024 + h * (w % 2)) >> 8) & 0xff,
                (OPJ_UINT8) ((h * w + 54 + 1024 + h * (w % 2)) >> 16) & 0xff,
                (OPJ_UINT8) ((h * w + 54 + 1024 + w * (w % 2)) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (54 + 1024) & 0xff, ((54 + 1024) >> 8) & 0xff,
                ((54 + 1024) >> 16) & 0xff,
                ((54 + 1024) >> 24) & 0xff);

        /* INFO HEADER */
        /* ------------- */
        fprintf(fdest, "%c%c%c%c", (40) & 0xff, ((40) >> 8) & 0xff, ((40) >> 16) & 0xff,
                ((40) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) ((w) & 0xff),
                (OPJ_UINT8) ((w) >> 8) & 0xff,
                (OPJ_UINT8) ((w) >> 16) & 0xff,
                (OPJ_UINT8) ((w) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) ((h) & 0xff),
                (OPJ_UINT8) ((h) >> 8) & 0xff,
                (OPJ_UINT8) ((h) >> 16) & 0xff,
                (OPJ_UINT8) ((h) >> 24) & 0xff);
        fprintf(fdest, "%c%c", (1) & 0xff, ((1) >> 8) & 0xff);
        fprintf(fdest, "%c%c", (8) & 0xff, ((8) >> 8) & 0xff);
        fprintf(fdest, "%c%c%c%c", (0) & 0xff, ((0) >> 8) & 0xff, ((0) >> 16) & 0xff,
                ((0) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (OPJ_UINT8) (h * w + h * (w % 2)) & 0xff,
                (OPJ_UINT8) ((h * w + h * (w % 2)) >> 8) & 0xff,
                (OPJ_UINT8) ((h * w + h * (w % 2)) >> 16) & 0xff,
                (OPJ_UINT8) ((h * w + h * (w % 2)) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
                ((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (7834) & 0xff, ((7834) >> 8) & 0xff,
                ((7834) >> 16) & 0xff, ((7834) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (256) & 0xff, ((256) >> 8) & 0xff,
                ((256) >> 16) & 0xff, ((256) >> 24) & 0xff);
        fprintf(fdest, "%c%c%c%c", (256) & 0xff, ((256) >> 8) & 0xff,
                ((256) >> 16) & 0xff, ((256) >> 24) & 0xff);

        if (image->comps[0].prec > 8) {
            adjustR = (int) image->comps[0].prec - 8;
           
        } else {
            adjustR = 0;
        }

        for (i = 0; i < 256; i++) {
            fprintf(fdest, "%c%c%c%c", i, i, i, 0);
        }

        for (i = 0; i < w * h; i++) {
            int r;

            r = image->comps[0].data[w * h - ((i) / (w) + 1) * w + (i) % (w)];
            r += (image->comps[0].sgnd ? 1 << (image->comps[0].prec - 1) : 0);
            if (adjustR > 0) {
                r = ((r >> adjustR) + ((r >> (adjustR - 1)) % 2));
            }
            if (r > 255) {
                r = 255;
            } else if (r < 0) {
                r = 0;
            }

            fprintf(fdest, "%c", (OPJ_UINT8) r);

            if ((i + 1) % w == 0) {
                for (pad = (w % 4) ? (4 - w % 4) : 0; pad > 0; pad--) { /* ADD */
                    fprintf(fdest, "%c", 0);
                }
            }
        }
        fclose(fdest);
    }

    return 0;
}

#endif

char jp2_to_bmp_2000(std::string &data, std::string filename, int offset) {
    opj_codec_t *c = NULL;
    opj_stream_t *s = NULL;
    opj_image_t *image = NULL;
    opj_dparameters_t param;

    do {
        opj_set_default_decoder_parameters(&param);

        s = opj_stream_create_memory_stream((char *) data.data() + offset, data.size() - offset);
        if (!s) {
            break;
        }
        c = opj_create_decompress(OPJ_CODEC_J2K);
        if (!c) {
            break;
        }
#ifdef DEBUG
        opj_set_info_handler(c, info_callback, 00);
        opj_set_warning_handler(c, warning_callback, 00);
        opj_set_error_handler(c, error_callback, 00);
#endif
        if (!opj_setup_decoder(c, &param)) {
            break;
        }
        if (!opj_read_header(s, c, &image)) {
            break;
        }
        if (!param.nb_tile_to_decode) {
            /* Optional if you want decode the entire image */
            if (!opj_set_decode_area(c, image, (OPJ_INT32)(param.DA_x0), (OPJ_INT32)(param.DA_y0),
                                     (OPJ_INT32)(param.DA_x1), (OPJ_INT32)(param.DA_y1))) {
                break;
            }
            /* Get the decoded image */
            if (!(opj_decode(c, s, image) && opj_end_decompress(c, s))) {
                break;
            }
        } else {
            if (!opj_get_decoded_tile(c, s, image, param.tile_index)) {
                break;
            }
        }

    } while (0);

    if (image) {
        imagetobmp(image, filename.c_str());
    }

    if (c) {
        opj_destroy_codec(c);
    }
    if (s) {
        opj_stream_destroy(s);
    }
    if (image) {
        opj_image_destroy(image);
    }
    return true;
}

char jp2_to_bmp(std::string &data, std::string filename) {
#if OOXX_JP2_DEBUG_LOG
    LOGV("Begin jp2_to_bmp");
#endif

#if USE_OPENJPEG
    size_t offset;

    if (data.length() <= 84) {
        return false;
    }

    std::string magic_jpeg("\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46", 10);
    std::string magic_jpeg2k("\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a", 10);
    std::string magic_jpeg2k_other("\xff\x4f\xff\x51", 4);

    int jpeg_version = 2000;

    offset = data.find(magic_jpeg2k_other.data(), 0, magic_jpeg2k_other.size());
    if (offset == std::string::npos) {
        offset = data.find(magic_jpeg2k.data(), 0, magic_jpeg2k.size());
        if (offset == std::string::npos) {
            offset = data.find(magic_jpeg.data(), 0, magic_jpeg.size());
            if (offset == std::string::npos) {
                // invalid jpeg files
                return false;
            }
            jpeg_version = 1992;
        }
    }

    if (jpeg_version == 2000)
        return jp2_to_bmp_2000(data, filename, offset);
    else if (jpeg_version == 1992) {
        using namespace cv;
        using namespace std;

        //todo: needs test
        Mat temp = imdecode(
                vector<unsigned char>(data.data() + offset, data.data() + data.length()), 1);
        imwrite(filename, temp);
    }
#endif

#if OOXX_JP2_DEBUG_LOG
    LOGV("End jp2_to_bmp");
#endif
    return true;
}
