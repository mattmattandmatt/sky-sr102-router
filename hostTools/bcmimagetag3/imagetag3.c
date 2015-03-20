/* Open Source Broadcom Image Builder version 0.31

 * Copyright (c) 2008 Axel Gembe <ago@bastart.eu.org>
 * Copyright (c) 2009 Daniel Dickinson <crazycshore@gmail.com>
 * Copyright (c) 2011 asbokid <ballymunboy@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <getopt.h>
#if defined(__MINGW32__)
#include "windows/byteswap.h"
#else
#include <byteswap.h>
#endif

#define OSS_BCM_IMG_BUILD_VER   "Open Source Broadcom Image Builder version 0.31\n" \
                                "Copyright (c) 2011 asbokid <ballymunboy@gmail.com>"
#define DEFAULT_SIGNATURE1      "Broadcom Corporatio"
#define DEFAULT_SIGNATURE2      "ver. 2.0"
#define DEFAULT_TAG_VER         "6"
#define DEFAULT_FLASH_START     0xBFC00000
#define DEFAULT_BLOCK_SIZE      64*1024
#define DEFAULT_VENDOR_ID       ""
#define DEFAULT_COMPILE_ID      ""
#define CRC_START               0xFFFFFFFF
#define MAX_FLASH_SIZE          16*1024*1024    /* we will malloc() this as working space */

/* Image component */
struct imagecomp {
    uint8_t         address[12];    /* Address of this component as ASCII */
    uint8_t         len[10];        /* Length of this component as ASCII */
};

/* Image tag */
struct imagetag {
    uint8_t         tagver[4];      /*   0 -   3: Version of the tag as ASCII (2) */
    uint8_t         sig1[20];       /*   4 -  23: BCM_SIGNATURE_1 */
    uint8_t         sig2[14];       /*  24 -  37: BCM_SIGNATURE_2 */
    uint8_t         chipid[6];      /*  38 -  43: Chip id as ASCIIZ (6368) */
    uint8_t         boardid[16];    /*  44 -  59: Board id as ASCIIZ (96368MVWG, etc...) */
    uint8_t         bigendian[2];   /*  60 -  61: "1" for big endian, "0" for little endian */
    uint8_t         imagelen[10];   /*  62 -  71: The length of all data that follows */
    struct imagecomp    cfe;        /*  72 -  93: The offset and length of CFE */
    struct imagecomp    rootfs;     /*  94 - 115: The offset and length of root file system */
    struct imagecomp    kernel;     /* 116 - 137: The offset and length of the kernel */
    uint8_t         dualimage[2];   /* 138 - 139: use "0" here */
    uint8_t         inactive[2];    /* 140 - 141: use "0" here */
    uint8_t         vendorid[20];   /* 142 - 161: vendor information */
    uint8_t         compileid[54];  /* 162 - 215: compilation information */
    uint32_t            imagecrc;   /* 216 - 219: crc of the image (net byte order) */
    uint32_t            rootfscrc;  /* 220 - 223: crc of the rootfs (net byte order) */
    uint32_t            kernelcrc;  /* 224 - 227: crc of the kernel (net byte order) */
    uint8_t         reserved1[8];   /* 228 - 235: reserved */
    uint32_t            headercrc;  /* 236 - 239: crc starting from sig1 until headercrc */
    uint8_t         reserved2[16];  /* 240 - 255: reserved */
};

static uint32_t crc32tab[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t crc32(uint32_t crc, uint8_t *data, size_t len)
{
    while (len--)
        crc = (crc >> 8) ^ crc32tab[(crc ^ *data++) & 0xFF];
    return crc;
}

size_t getlen(FILE *fp)
{
    size_t retval, curpos;

    if (!fp)
        return 0;
    curpos = ftell(fp);
    fseek(fp, 0, SEEK_END);
    retval = ftell(fp);
    fseek(fp, curpos, SEEK_SET);
    return retval;
}

int parsetag(struct imagetag tag) {
    printf("Tag Version  : %s\n", tag.tagver);
    printf("Signature1   : %s\n", tag.sig1);
    printf("Signature2   : %s\n", tag.sig2);
    printf("Chip ID      : %s\n", tag.chipid);
    printf("Board ID     : %s\n", tag.boardid);
    printf("Big Endian   : ");
    if(tag.bigendian[0]=='1') printf("true\n");
    else if(tag.bigendian[0]=='0') printf("false\n");
    else printf("invalid value\n");
    printf("Image size   : %08lx, %s\n", strtoul((char*)tag.imagelen, NULL,10), tag.imagelen);
    printf("CFE Address  : %08lx, %s\n", strtoul((char*)tag.cfe.address, NULL,10), tag.cfe.address);
    printf("CFE Length   : %08lx, %s\n", strtoul((char*)tag.cfe.len, NULL,10), tag.cfe.len);
    printf("Flash Root Address: %08lx, %s\n", strtoul((char*)tag.rootfs.address, NULL,10), tag.rootfs.address);
    printf("Flash Root Length: %08lx, %s\n", strtoul((char*)tag.rootfs.len, NULL,10), tag.rootfs.len);
    printf("Flash Kernel Address: %08lx, %s\n", strtoul((char*)tag.kernel.address, NULL, 10), tag.kernel.address);
    printf("Flash Kernel Length: %08lx, %s\n", strtoul((char*)tag.kernel.len, NULL,10), tag.kernel.len);
    printf("Vendor information: %s\n", tag.vendorid);
    printf("Compile info: %s\n", tag.compileid);
    printf("Image  CRC: %08x\n", bswap_32(tag.imagecrc));
    printf("Header CRC: %08x\n", bswap_32(tag.headercrc));
    printf("Kernel CRC: %08x\n", bswap_32(tag.kernelcrc));
    printf("Rootfs CRC: %08x\n", bswap_32(tag.rootfscrc));

    return 0;
}

int hexdumptag(struct imagetag tag) {
    uint8_t *tagptr = (uint8_t *) &tag;
    uint32_t i,j;
    for(i=0;i<sizeof(tag);i+=16) {
        printf("\n%07x: ", i);
        for(j=0; j<16; j+=2)
            printf("%02x%02x ", *(tagptr+i+j), *(tagptr+i+j+1));
        printf(" ");
        for(j=0; j<16; j++) {
            if(*(tagptr+i+j)<32 || *(tagptr+i+j)>127)
                printf(".");
            else printf("%c", *(tagptr+i+j));
        }
    }
    printf("\n\n");
    return 0;
}

int tagfile (const char *kernel, const char *rootfs, const char *cfe, const char *outf,
    const char *boardid, const char *chipid, const uint32_t flstart, uint8_t includecfe, uint8_t littleendian,
    const char *ver, const char *signature1, const char *signature2, const uint32_t flash_bs,
    const char *vendorid, const char *compileid) {

    struct imagetag tag;
    FILE *kernelfile, *rootfsfile, *cfefile, *outfile;
    size_t kerneloff, kernellen, rootfsoff, rootfslen, imagelen;
    size_t cfeoff, cfelen, cfeadd;
    uint32_t kernelcrc, rootfscrc, imagecrc, headercrc;
    uint8_t *flashmem = NULL;

    cfeoff = flstart;
    kernelfile = rootfsfile = outfile = NULL;
    kernelcrc = rootfscrc = imagecrc = headercrc = CRC_START;

    if (strlen(boardid) >= sizeof(tag.boardid)) {
        fprintf(stderr, "Board id is too long! (max %lx bytes)\n", (unsigned long int) sizeof(tag.boardid));
        return 1;
    }

    if (strlen(chipid) >= sizeof(tag.chipid)) {
        fprintf(stderr, "Chip id is too long! (max %lx bytes)\n", (unsigned long int) sizeof(tag.chipid));
        return 1;
    }

    if (strlen(vendorid) >= sizeof(tag.vendorid)) {
        fprintf(stderr, "Vendor info is too long! (max %lx bytes)\n", (unsigned long int) sizeof(tag.vendorid));
        return 1;
    }

    if (strlen(compileid) >= sizeof(tag.compileid)) {
        fprintf(stderr, "Compilation info is too long! (max %lx bytes)\n", (unsigned long int) sizeof(tag.compileid));
        return 1;
    }

    if (kernel && !rootfs) {
        fprintf(stderr, "Incompatible command line parameters: kernel file provided but no rootfs file.\n");
        return 1;
    }

    if (kernel && !(kernelfile = fopen(kernel, "rb"))) {
        fprintf(stderr, "Unable to open kernel file \"%s\"\n", kernel);
        return 1;
    }

    if (rootfs && !(rootfsfile = fopen(rootfs, "rb"))) {
        fprintf(stderr, "Unable to open rootfs file \"%s\"\n", rootfs);
        return 1;
    }

    if (cfe && !(cfefile = fopen(cfe, "rb"))) {
        fprintf(stderr, "Unable to open CFE file \"%s\"\n", cfe);
        return 1;
    }

    if (!outf || !(outfile = fopen(outf, "wb+"))) {
        fprintf(stderr, "Unable to open image output file \"%s\"\n", outf);
        return 1;
    }

//  calloc() enough working memory for an entire flash image

    flashmem = calloc(MAX_FLASH_SIZE, sizeof(uint8_t));
    if (flashmem == NULL) {
        fprintf(stderr, "Couldn\'t allocate 0x%0x bytes for image memory\n", MAX_FLASH_SIZE);
        return 1;
    }
    memset(&tag, 0, sizeof(struct imagetag));


//  Calculate cfe address and length

    cfeoff = flstart;
    cfelen = getlen(cfefile);

    if(includecfe || !rootfsfile) {
        fprintf(stderr, "Caution: Including an incompatible CFE in the firmware image can be dangerous!\n\n");
        cfeadd = cfelen;
    }
    else
        cfeadd = 0; 

//  Calculate rootfs address and length.

    rootfsoff = cfeoff + cfelen + sizeof(tag) + flash_bs - (cfelen % flash_bs);
    rootfslen = getlen(rootfsfile);

//  Calculate kernel address and length

    kerneloff = rootfsoff + rootfslen;
    kernellen = getlen(kernelfile);

//  Calculate image length -- we don't include the (256 byte) tag header

    imagelen = rootfslen + kernellen;

//  Read the CFE into working flash image memory

    if(includecfe || !rootfsfile) {
        imagelen += cfelen;
        if (fread(flashmem+sizeof(tag),sizeof(uint8_t), cfelen, cfefile) != cfelen) {
            fprintf(stderr, "Read error from CFE file %s\n", cfe);
            return 1;
        }
    }

//  Read the RootFS and kernel into working image memory

    if(rootfsfile) {
        if (fread(flashmem + cfeadd + sizeof(tag),sizeof(uint8_t), rootfslen, rootfsfile) != rootfslen) {
            fprintf(stderr, "Read error from rootfs file %s\n", rootfs);
            return 1;
        }
        if (fread(flashmem + cfeadd + sizeof(tag) + rootfslen,sizeof(uint8_t), kernellen, kernelfile) != kernellen) {
            fprintf(stderr, "Read error from kernelfile %s\n", kernel);
            return 1;
        }
    }
    
//  Initialise the CRC32s

    kernelcrc = rootfscrc = imagecrc = headercrc = CRC_START;

//  Calculate the rootfs CRC and kernel CRC

    rootfscrc = crc32(rootfscrc, flashmem + sizeof(tag) + cfeadd, rootfslen);
    kernelcrc = crc32(kernelcrc, flashmem + sizeof(tag) + cfeadd + rootfslen, kernellen);
    
//  Calculate image CRC

    if(rootfsfile)      //  rootfsfile implies kernelfile
        imagecrc = crc32(imagecrc, flashmem + sizeof(tag), cfeadd + rootfslen + kernellen);
    else                    // if !rootfsfile then imagecrc is only calculated on the CFE
        imagecrc = crc32(imagecrc, flashmem + sizeof(tag), cfeadd);

//  Close the input files

    fclose(cfefile);
    if(rootfsfile) {
        fclose(rootfsfile);
        fclose(kernelfile);
    }

//  Build the tag

    strcpy((char *)tag.tagver, ver);
    strncpy((char *)tag.sig1, signature1, sizeof(tag.sig1) - 1);
    strncpy((char *)tag.sig2, signature2, sizeof(tag.sig2) - 1);
    strcpy((char *)tag.chipid, chipid);
    strcpy((char *)tag.boardid, boardid);
    if(littleendian) strcpy((char *)tag.bigendian, "0");
    else strcpy((char *)tag.bigendian, "1");
    sprintf((char *)tag.imagelen, "%lu", (unsigned long int) imagelen);

    if (includecfe || !rootfsfile) {
        sprintf((char *)tag.cfe.address, "%lu", (unsigned long int) cfeoff);
        sprintf((char *)tag.cfe.len, "%lu", (unsigned long int) cfelen);
    }
    else {
        sprintf((char *)tag.cfe.address, "%lu", (unsigned long) 0);
        sprintf((char *)tag.cfe.len, "%lu", (unsigned long) 0);
    }

    if (rootfsfile) {
        sprintf((char *)tag.rootfs.address, "%lu", (unsigned long int) rootfsoff);
        sprintf((char *)tag.rootfs.len, "%lu", (unsigned long int) rootfslen);
        sprintf((char *)tag.kernel.address, "%lu", (unsigned long int) kerneloff);
        sprintf((char *)tag.kernel.len, "%lu", (unsigned long int) kernellen);
    }
    else {
        sprintf((char *)tag.rootfs.address, "%lu", (unsigned long) 0);
        sprintf((char *)tag.rootfs.len, "%lu", (unsigned long) 0 );
        sprintf((char *)tag.kernel.address, "%lu", (unsigned long) 0);
        sprintf((char *)tag.kernel.len, "%lu", (unsigned long) 0);
    }

    strcpy((char *)tag.vendorid, vendorid);
    strcpy((char *)tag.compileid, compileid);

    if (littleendian) {
        tag.kernelcrc = kernelcrc;
        tag.rootfscrc = rootfscrc;
        tag.imagecrc = imagecrc;
        headercrc = crc32(CRC_START, (uint8_t*)&tag, sizeof(tag) - 20);
        tag.headercrc = headercrc;
    }
    else {
        tag.kernelcrc = bswap_32(kernelcrc);
        tag.rootfscrc = bswap_32(rootfscrc);
        tag.imagecrc = bswap_32(imagecrc);
        headercrc = crc32(CRC_START, (uint8_t*)&tag, sizeof(tag) - 20);
        tag.headercrc = bswap_32(headercrc);
    }

//  copy tag into working flash memory

    memcpy(flashmem, &tag, sizeof(tag));

//  parse tag

    parsetag(tag);

//  debug dump tag to stdout

#ifdef DEBUG
    hexdumptag(tag);
#endif

//  write working flash memory to output file

    if(fwrite(flashmem, sizeof(uint8_t), imagelen + sizeof(tag), outfile) != imagelen + sizeof(tag)) {
        fprintf(stderr, "write error to %s\n", outf);
        return 1;
    }
    fclose(outfile);
    printf("Image file of %lx bytes successfully created as %s\n\n", (unsigned long int) imagelen + sizeof(tag), outf);

	if(flashmem)
		free(flashmem);

    return 0;
}

int main(int argc, char **argv)
{
    char *kernel, *rootfs, *cfe, *outfile, *boardid, *chipid;
	char *signature1, *signature2, *tagver, *vendorid, *compileid;
    uint32_t flashstart, blocksize;
    uint8_t includecfe_flag = 0, littleendian_flag = 0;
    struct imagetag tag;
	int retval = 0;

    static struct option longopts[] = {
        {"kernelfile",  required_argument, 0, 'a'},
        {"rootfsfile",  required_argument, 0, 'b'},
        {"cfefile",     required_argument, 0, 'c'},
        {"output",      required_argument, 0, 'd'},
        {"board",       required_argument, 0, 'e'},
        {"chip",        required_argument, 0, 'f'},
        {"start",       required_argument, 0, 'g'},
        {"help",        no_argument,       0, 'h'},
        {"include-cfe", no_argument,       0, 'i'},
        {"blocksize",   required_argument, 0, 'k'},
        {"littleendian",no_argument,       0, 'l'},
        {"tagversion",  required_argument, 0, 'm'},
        {"vendorid",    required_argument, 0, 'p'},
        {"compileid",   required_argument, 0, 'q'},
        {"signature1",  required_argument, 0, 'r'},
        {"signature2",  required_argument, 0, 's'},
        {"version",     no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    static char usage_msg[] = "Usage: {-h|--help|-v|--version}\n\t[--littleendian]\n"
        "\t--chip <chipid> -- chip id {6368|6348|6358|6368}\n\t--board <boardid> -- board id {e.g. 96368MVWG}\n"
        "\t--output <filename> -- cfefile <filename>\n\t--rootfsfile <filename> -- kernelfile <filename>\n\t"
        "[-i|--include-cfe]\n\n";

    kernel=rootfs=cfe=outfile=boardid=chipid=signature1=signature2=tagver=vendorid=compileid=NULL;
    flashstart = DEFAULT_FLASH_START;
    vendorid = DEFAULT_VENDOR_ID;
    compileid = DEFAULT_COMPILE_ID;
    blocksize = DEFAULT_BLOCK_SIZE;

    signature1 = (char *) malloc(sizeof(tag.sig1));
    if (!signature1) {
        perror("malloc");
        return 1;
    }
    signature2 = (char *) malloc(sizeof(tag.sig2));
    if (!signature2) {
        perror("malloc");
        return 1;
    }

    tagver = (char *) malloc(sizeof(tag.tagver));
    if (!tagver) {
        perror("malloc");
        return 1;
    }
    vendorid = (char *) malloc(sizeof(tag.vendorid));
    if (!vendorid) {
        perror("malloc");
        return 1;
    }
    compileid = (char *) malloc(sizeof(tag.compileid));
    if (!compileid) {
        perror("malloc");
        return 1;
    }

    strcpy(signature1, DEFAULT_SIGNATURE1);
    strcpy(signature2, DEFAULT_SIGNATURE2);
    strcpy(tagver, DEFAULT_TAG_VER);
    strcpy(vendorid, DEFAULT_VENDOR_ID);
    strcpy(compileid, DEFAULT_COMPILE_ID);

    printf("%s\n", OSS_BCM_IMG_BUILD_VER);

    while (1) {
        int32_t optidx = 0;
        int8_t c = getopt_long(argc,argv,"a:b:c:d:e:f:g:hik:lm:p:q:r:s:v",longopts,&optidx);
        if (c == -1)
            break;

        switch (c) {
            case 'a': kernel = optarg;
                  break;
            case 'b': rootfs = optarg;
                  break;
            case 'c': cfe = optarg;
                  break;
            case 'd': outfile = optarg;
                  break;
            case 'e': boardid = optarg;
                  break;
            case 'f': chipid = optarg;
                  break;
            case 'g': flashstart = strtoul(optarg, NULL, 16);
                  break;
            case 'i': includecfe_flag = 1;
                  break;
            case 'k': blocksize = atoi(optarg);
                  if(blocksize != 64 && blocksize != 128) {
                    fprintf(stderr, "blocksize must be 64KB or 128KB\n");
                    return 1;
                  }
                  blocksize *= 1024;
                  break;
            case 'l': littleendian_flag = 1;
                  break;
            case 'm': strcpy(tagver,optarg);
                  break;
            case 'p': strcpy(vendorid,optarg);
                  break;
            case 'q': strcpy(compileid,optarg);
                  break;
            case 'r': strcpy(signature1,optarg);
                  break;
            case 's': strcpy(signature2,optarg);
                  break;
            case 'v': 
                  printf("(c) 2008 Axel Gembe, (c) 2009 Daniel Dickinson, (c) 2011 asbokid\n");
                  return 0;
            case 'h':
                  printf("  -h, --help                 Displays this text\n");
                  printf("  -l, --littleendian         Build little endian image (default: FALSE)\n");  
                  printf("  -v, --version              Print the version number\n");            
                  printf("  --chip <chipid>            Chip id to set in the image (e.g. \"6368\")\n");
                  printf("  --board <boardid>          Board id to set in the image (e.g. \"96368MVWG\")\n");
                  printf("  --blocksize <size>         Flash erase block size in KB {64|128}\n");
                  printf("  --output <filename>        Output image file name\n");                
                  printf("  --start <flashstart>       Flash start address (default: 0x%08x)\n",DEFAULT_FLASH_START);
                  printf("  --tagversion <version>     Tag version (default: \"%s\")\n", DEFAULT_TAG_VER);
                  printf("  --signature1 <sig>         Sig #1 of tag (default: \"%s\")\n", DEFAULT_SIGNATURE1);
                  printf("  --signature2 <sig>         Sig #2 of tag (default: \"%s\")\n", DEFAULT_SIGNATURE2);               
                  printf("  --vendorid <id>            Vendor information (default: \"%s\")\n", DEFAULT_VENDOR_ID);
                  printf("  --compileid <info>         Firmware compile info (default: \"%s\")\n", DEFAULT_COMPILE_ID);
                  printf("  --cfefile <filename>       CFE image name\n");                
                  printf("  --kernelfile <filename>    LZMA compressed kernel image name\n");
                  printf("  --rootfsfile <filename>    Root file system image name\n");
                  printf("  -i, --include-cfe          Add CFE to kernel and rootfs image\n");
                  return 0;
            default :
            case '?': fprintf(stderr, "%s", usage_msg);
                  return 1;
            }
    }

    if(!outfile || !cfe || (rootfs && !kernel) || !boardid || !chipid || !blocksize ) {
        fprintf(stderr, "Required input parameters are missing\n");
        fprintf(stderr, "%s", usage_msg);
        return(1);
    }

    retval = tagfile(kernel,rootfs,cfe,outfile,boardid,chipid,flashstart,includecfe_flag,littleendian_flag,
               tagver,signature1,signature2,blocksize,vendorid,compileid);

	if(signature1)
		free(signature1);
	if(signature2)
		free(signature2);
	if(tagver)
		free(tagver);
	if(vendorid)
		free(vendorid);
	if(compileid)
		free(compileid);

	return retval;

}
