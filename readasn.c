#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "readasn.h"

static long pos = 0;

static char   (*tagname)[MAXLEN];

static int use_tagnames = TRUE;

char nrt0201_tagname_map[MAXTAGS][MAXLEN];

char rap01XX_tagname_map[MAXTAGS][MAXLEN];

char tap03le09_tagname_map[MAXTAGS][MAXLEN];

char tap03ge10_tagname_map[MAXTAGS][MAXLEN];

uchar *buffin_str = NULL, *buffin_str_tmp = NULL;

long buffin_str_len = 0;

static int decode_asn(FILE *file, long size, int is_indef, int is_root, int recno, int is_tap, int depth);

static int decode_size(FILE *file, asn1item *a_item);

static int decode_tag(FILE *file, asn1item *a_item);

static void bcd_2_hexa(char *str2, const uchar *str1, const int len);

static int is_printable(uchar *str, long len);

static void help(char *program_name);

static int get_file_type(FILE *file, int *file_type, gsmainfo_t *gsminfo);

static void printout(int depth, long pos, int recno, const char *format, ...) {

    va_list args;
    va_start(args, format);
    printf("%d|", recno);
    vfprintf(stdout, format, args);
    va_end(args);
}

int main(int argc, char **argv) {

    FILE *file = NULL;
    char *filename = "";
    long size = 0;
    int file_type = FT_UNK;
    char *program_name = argv[0];
    gsmainfo_t gsmainfo;

    memset(&gsmainfo, 0x00, sizeof(gsmainfo));

    filename = argv[1];

    if (argc != 2 && argc != 3)
        help(program_name);

    if (argc == 3) {

        if (argv[1][0] == '-' && argv[1][1] == 'n')
            use_tagnames = FALSE;
        else
            help(program_name);

        filename = argv[2];
    }

    if ((file = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (get_file_type(file, &file_type, &gsmainfo) != 0) {
        fprintf(stderr, "Error getting the type of file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    printf("File type: %s ver: %d, rel: %d, rap_ver: %d, rap_rel: %d\n",
           (file_type == FT_TAP ? "TAP" : (file_type == FT_NOT ? "NOT" : (file_type == FT_RAP ? "RAP" : (file_type ==
                                                                                                         FT_NRT ? "NRT"
                                                                                                                : "UNK")))),
           gsmainfo.ver, gsmainfo.rel, gsmainfo.rap_ver, gsmainfo.rap_rel);

    if (use_tagnames && file_type != FT_UNK) {
        tagid_init();
        if (
                ((file_type == FT_TAP || file_type == FT_NOT || file_type == FT_RAP) && gsmainfo.ver == 3) ||
                (file_type == FT_ACK && gsmainfo.ver == 0)
                ) {
            if (gsmainfo.rel <= 9) {
                tagname = tap03le09_tagname_map;
            } else {
                tagname = tap03ge10_tagname_map;
            }

            if (((file_type == FT_RAP || file_type == FT_ACK) && gsmainfo.rap_ver == 1)) {
                if (merge_tap_rapids(tagname, rap01XX_tagname_map) != 0) {
                    exit(EXIT_FAILURE);
                }
            }

        } else if (file_type == FT_NRT) {
            tagname = nrt0201_tagname_map;
        } else {
            use_tagnames = FALSE;
        }
    } else {
        use_tagnames = FALSE;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error moving to the end of the file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error moving to the beginning of the file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((decode_asn(
            file,
            size,
            FALSE,
            (file_type == FT_UNK ? TRUE : FALSE),
            (file_type == FT_UNK ? 1 : 0),
            file_type,
            0
    )
        ) == -1) {

        exit(EXIT_FAILURE);
    }

    (void) fclose(file);

    if (buffin_str) {
        free(buffin_str);
    }

    return (EXIT_SUCCESS);
}

static int decode_asn(FILE *file, long size, int is_indef, int is_root, int recno, int file_type, int depth) {

    asn1item a_item;
    int is_root_loc = is_root, recno_loc = recno;
    long long sum_up = 0;
    long loc_pos = pos, i = 0;

    memset(&a_item, 0x00, sizeof(a_item));

    while (size > 0 || is_indef) {

        if (decode_tag(file, &a_item) == -1) {
            fprintf(stderr, "Error decoding tag at position: %ld\n", pos);
            return -1;
        }

        if (decode_size(file, &a_item) == -1) {
            fprintf(stderr, "Error decoding size at position: %ld\n", pos);
            return -1;
        }

        if (a_item.tag == 0 && a_item.size == 0 && is_indef) {
            break;
        } else if (a_item.tag_x[0] == 0x00 && a_item.size != 0 && !is_indef) {

            loc_pos++;
            pos = loc_pos;
            size--;
            if (fseek(file, pos, SEEK_SET) != 0) {
                fprintf(stderr, "Error moving 1 byte back in file: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
            }
            continue;
        }

        {

            if (a_item.pc == 0) {

                printout(depth, loc_pos, recno, "%s|",
                         use_tagnames ? tagname[a_item.tag][0] == '\0' ? "Unknown" : tagname[a_item.tag] : "");

                if (!buffin_str_len) {
                    if ((buffin_str = (uchar *) malloc((size_t) a_item.size + 1 * sizeof(uchar))) == NULL) {
                        fprintf(stderr, "Couldn't allocate memory. Size too long at pos: %ld\n", pos);
                        return -1;
                    }
                    buffin_str_len = a_item.size;
                } else {
                    if (a_item.size > buffin_str_len) {
                        if ((buffin_str_tmp = (uchar *) realloc(buffin_str,
                                                                (size_t) a_item.size + 1 * sizeof(uchar))) == NULL) {
                            fprintf(stderr, "Couldn't allocate memory. Size too long at pos: %ld\n", pos);
                            return -1;
                        }
                        buffin_str = buffin_str_tmp;
                        buffin_str_len = a_item.size;
                    }
                }

                (void) fread(buffin_str, sizeof(uchar), (size_t) a_item.size, file);
                if (feof(file) != 0) {
                    fprintf(stderr, "Found end of file too soon at position: %ld\n", pos);
                    if (buffin_str) free(buffin_str);
                    return -1;
                }

                if ((size_t) a_item.size <= sizeof(sum_up)) {
                    sum_up = 0;
                    for (i = 0; i < a_item.size; i++) {
                        sum_up <<= 8;
                        sum_up += (long) buffin_str[i];
                    }

                    printf("%lld|", sum_up);
                }

                if (is_printable(buffin_str, a_item.size)) {
                    for (i = 0; i < a_item.size; i++)
                        printf("%c", buffin_str[i]);
                }
                printf("|");
                for (i = 0; i < a_item.size; i++)
                    printf("%02x", (unsigned int) buffin_str[i]);
                printf("|\n");

                pos += a_item.size;

            } else {

                if (a_item.size_x[0]) {

                    if (file_type == FT_UNK) {
                        is_root_loc = FALSE;
                        recno_loc = recno;
                    }
                    if (file_type == FT_TAP) {
                        is_root_loc = (a_item.tag == 3 ? TRUE : FALSE);
                        recno_loc = (a_item.tag == 3 ? 1 : recno);
                    }
                    if (file_type == FT_NOT) {
                        is_root_loc = FALSE;
                        recno_loc = recno;
                    }
                    if (file_type == FT_NRT) {
                        is_root_loc = (a_item.tag == 2 ? TRUE : FALSE);
                        recno_loc = (a_item.tag == 2 ? 1 : recno);
                    }
                    if (file_type == FT_RAP) {
                        is_root_loc = (a_item.tag == 536 ? TRUE : FALSE);
                        recno_loc = (a_item.tag == 536 ? 1 : recno);
                    }
                    if (file_type == FT_ACK) {
                        is_root_loc = FALSE;
                        recno_loc = recno;
                    }

                    if ((decode_asn(
                            file,
                            a_item.size,
                            (a_item.size == 0 ? TRUE : FALSE),
                            is_root_loc,
                            recno_loc,
                            file_type,
                            depth + 1)
                        ) == -1) {
                        return -1;
                    }
                }
            }

            size -= pos - loc_pos;

        }

        loc_pos = pos;

        if (is_root) {
            recno++;
        }

    }

    return 0;
}

static int decode_tag(FILE *file, asn1item *a_item) {

    uchar buffin;
    int i;

    a_item->tag = 0;

    buffin = (uchar) fgetc(file);
    if (feof(file) != 0) {
        fprintf(stderr, "Found end of file too soon at position: %ld\n", pos);
        return -1;
    }
    pos++;

    a_item->class = (unsigned) buffin >> 6;
    a_item->pc = (unsigned) (buffin >> 5) & 0x1;
    a_item->tag_x[0] = buffin;
    a_item->tag_l = 1;

    if ((buffin & 0x1F) == 0x1F) {

        for (i = 1; i <= 4; i++) {
            buffin = (uchar) fgetc(file);
            if (feof(file) != 0) {
                fprintf(stderr, "Found end of file too soon at position: %ld\n", pos);
                return -1;
            }
            pos++;

            a_item->tag <<= 7;
            a_item->tag += (int) (buffin & 0x7F);
            a_item->tag_x[i] = buffin;
            a_item->tag_l += 1;

            if ((buffin >> 7) == 0)
                break;

        }

        if (i > 3) {
            fprintf(stderr, "Found tag bigger than 4 bytes at position: %ld\n", pos);
            return -1;
        }

    } else {

        a_item->tag = (int) buffin & 0x1F;
    }

    bcd_2_hexa(a_item->tag_h, a_item->tag_x, a_item->tag_l);

    return 0;

}

static int decode_size(FILE *file, asn1item *a_item) {

    uchar buffin;
    int i;

    a_item->size = 0;

    buffin = (uchar) fgetc(file);
    if (feof(file) != 0) {
        if (a_item->tag_x[0] == 0x00) {
            a_item->size = 1;
            return 0;
        }
        fprintf(stderr, "Found end of file too soon at position: %ld\n", pos);
        return -1;
    }
    pos++;

    a_item->size_x[0] = buffin;
    a_item->size_l = 1;

    if (buffin >> 7) {

        for (i = 1; (i <= (int) (a_item->size_x[0] & 0x7F)) && (i <= 4); i++) {
            buffin = (uchar) fgetc(file);
            if (feof(file) != 0) {
                fprintf(stderr, "Found end of file too soon at position: %ld\n", pos);
                return -1;
            }
            pos++;

            a_item->size <<= 8;
            a_item->size += (int) buffin;
            a_item->size_x[i] = buffin;
            a_item->size_l += 1;
        }

        if (i > 7) {
            fprintf(stderr, "Found size bigger than 8 bytes at position: %ld\n", pos);
            return -1;
        }

    } else {

        a_item->size = (int) (buffin);
    }

    bcd_2_hexa(a_item->size_h, a_item->size_x, a_item->size_l);

    return 0;

}

static void bcd_2_hexa(char *str2, const uchar *str1, const int len) {

    int i = 0;

    for (i = 0; i < len; i++)
        sprintf(&str2[i * 2], "%02x", (unsigned) str1[i]);

    str2[i * 2] = '\0';

}

static int is_printable(uchar *str, long len) {

    long i = 0, eol = 0;

    for (i = 0; i < len; i++) {

        if (!isprint(str[i]) && str[i] != 0x0a)
            return 0;
        if (str[i] == 0x0a)
            eol++;
    }

    if (eol > 0 && len < 7)
        return 0;

    return 1;
}

static int get_file_type(FILE *file, int *file_type, gsmainfo_t *gsmainfo) {

    uchar buffin_str[200];
    int buffin_len = 200, i = 0;

    memset(buffin_str, 0x00, sizeof(buffin_str));

    if (file == NULL || file_type == NULL || gsmainfo == NULL) {
        fprintf(stderr, "Passed NULL Arguments");
        return -1;
    }

    if (fread(buffin_str, sizeof(uchar), (size_t) buffin_len, file) == 0) {
        fprintf(stderr, "Error reading file at position: %d\n", 1);
        return -1;
    }

    switch (buffin_str[0]) {
        case 0x61:
            for (i = 1; i < 150; i++) {
                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x81 &&
                    buffin_str[i + 2] == 0x49 &&
                    buffin_str[i + 3] == 0x01) {
                    gsmainfo->ver = (int) buffin_str[i + 4];
                }

                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x81 &&
                    buffin_str[i + 2] == 0x3d &&
                    buffin_str[i + 3] == 0x01) {
                    gsmainfo->rel = (int) buffin_str[i + 4];
                    *file_type = FT_TAP;
                    break;
                }

            }
            for (i = 1; i < 28; i++) {
                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x29 &&
                    buffin_str[i + 2] == 0x01) {
                    gsmainfo->ver = (int) buffin_str[i + 3];
                }

                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x25 &&
                    buffin_str[i + 2] == 0x01) {
                    gsmainfo->rel = (int) buffin_str[i + 3];
                    *file_type = FT_NRT;
                    break;
                }
            }
            break;
        case 0x62:
            for (i = 1; i < 150; i++) {
                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x81 &&
                    buffin_str[i + 2] == 0x49 &&
                    buffin_str[i + 3] == 0x01) {
                    gsmainfo->ver = (int) buffin_str[i + 4];
                }

                if (buffin_str[i] == 0x5f &&
                    buffin_str[i + 1] == 0x81 &&
                    buffin_str[i + 2] == 0x3d &&
                    buffin_str[i + 3] == 0x01) {
                    gsmainfo->rel = (int) buffin_str[i + 4];
                    *file_type = FT_NOT;
                    break;
                }

            }
            break;
        case 0x7f:
            if (buffin_str[1] == 0x84 && buffin_str[2] == 0x16) {
                for (i = 1; i < 150; i++) {
                    if (buffin_str[i] == 0x5f &&
                        buffin_str[i + 1] == 0x81 &&
                        buffin_str[i + 2] == 0x49 &&
                        buffin_str[i + 3] == 0x01) {
                        gsmainfo->ver = (int) buffin_str[i + 4];
                    }

                    if (buffin_str[i] == 0x5f &&
                        buffin_str[i + 1] == 0x81 &&
                        buffin_str[i + 2] == 0x3d &&
                        buffin_str[i + 3] == 0x01) {
                        gsmainfo->rel = (int) buffin_str[i + 4];
                    }

                    if (buffin_str[i] == 0x5f &&
                        buffin_str[i + 1] == 0x84 &&
                        buffin_str[i + 2] == 0x20 &&
                        buffin_str[i + 3] == 0x01) {
                        gsmainfo->rap_ver = (int) buffin_str[i + 4];
                    }

                    if (buffin_str[i] == 0x5f &&
                        buffin_str[i + 1] == 0x84 &&
                        buffin_str[i + 2] == 0x1f &&
                        buffin_str[i + 3] == 0x01) {
                        gsmainfo->rap_rel = (int) buffin_str[i + 4];
                        *file_type = FT_RAP;
                        break;
                    }

                }
            }
            if (buffin_str[1] == 0x84 && buffin_str[2] == 0x17) {
                gsmainfo->rap_ver = 1;
                gsmainfo->rap_rel = 5;
                *file_type = FT_ACK;
            }
            break;
        default:
            *file_type = FT_UNK;
    }

    return 0;
}

static void help(char *program_name) {

    exit(EXIT_FAILURE);
}
