/*
 * A simple flash mapping code for BCM963xx board flash memory
 * It is simple because it only treats all the flash memory as ROM
 * It is used with chips/map_rom.c
 *
 *  Song Wang (songw@broadcom.com)
 */

/*
	Added Blocks:
	mtd-AuxFS - Override values
	mtd-cfeFS
	mtd-nvramFS
	mtd-LastSectFS
	mtd-AllFS
*/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/io.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
//#include <linux/config.h>

#include <board.h>
#include <bcmTag.h>
#include <bcm_map_part.h>
#define  VERSION	"1.0"

extern PFILE_TAG kerSysImageTagGet(void);

#if !defined(CONFIG_BRCM_IKOS)
extern int kerSysEraseFlash(unsigned long eraseaddr,unsigned long len);
extern int kerSysWriteToFlash(unsigned long toaddr,void * fromaddr, unsigned long len);
#endif

#define  BCM_MTD_VERSION	"2.0"	/* NOR FLASH ONLY */

const char * null_mtd_c = "NULLMTD";

/*
 * MTD Driver Entry Points using kerSys interface to flash_api
 *
 * Assumption:
 * - Single region with all sectors of the same size per MTD device registered.
 * - BankSize = 2
 *
 * Runtime spcification of device size, offset using Flash Partition Info.
 */

static int bcm63xx_erase_invalid(struct mtd_info *mtd, struct erase_info *instr)
{
    const char * mtdname_p = (char*)null_mtd_c;
    if ( mtd ) mtdname_p = mtd->name;
    printk("ERROR: bcm63xx_erase_invalid( mtd[%s])\n", mtdname_p );

	/* Proceed as if done */
    instr->state = MTD_ERASE_DONE;
    mtd_erase_callback( instr );

    return (0);
}

static int bcm63xx_erase(struct mtd_info *mtd, struct erase_info *instr)
{
    unsigned long flash_base;
    if ( mtd == (struct mtd_info *)NULL )
{
        printk("ERROR: bcm63xx_erase( mtd[%s])\n", null_mtd_c);
        return (-EINVAL);
        }

    if ( instr->addr + instr->len > mtd->size )
    {
        printk("ERROR: bcm63xx_erase( mtd[%s]) invalid region\n", mtd->name);
        return (-EINVAL);
    }

    flash_base = (unsigned long)mtd->priv;

#if !defined(CONFIG_BRCM_IKOS)
    if ( kerSysEraseFlash( flash_base + instr->addr, instr->len) )
        return (-EINVAL);
#endif
	
    instr->state = MTD_ERASE_DONE;
    mtd_erase_callback( instr );

    return (0);
}

/*
static int bcm63xx_point_invalid(struct mtd_info *mtd, loff_t from,
			size_t len, size_t *retlen, u_char **mtdbuf)
{
    return (-EINVAL);
}

static void bcm63xx_unpoint_invalid(struct mtd_info *mtd, u_char * addr,
			loff_t from, size_t len)
{
}

*/
static int bcm63xx_read(struct mtd_info *mtd, loff_t from, size_t len,
			size_t *retlen, u_char *buf)
{
    unsigned long flash_base;
    *retlen = 0;
    if ( mtd == (struct mtd_info *)NULL )
    {
        printk("ERROR: bcm63xx_read( mtd[%s])\n", null_mtd_c);
        return (-EINVAL);
    }
    flash_base = (unsigned long)mtd->priv;
	
    *retlen = kerSysReadFromFlash(buf, flash_base + from, len); 
	
		return 0;
	}

static int bcm63xx_write_invalid(struct mtd_info *mtd, loff_t to, size_t len,
			size_t *retlen, const u_char *buf)
{
    const char * mtdname_p = (char*)null_mtd_c;
    *retlen = 0;
    if ( mtd ) mtdname_p = mtd->name;
    printk("ERROR: bcm63xx_write_invalid( mtd[%s])\n", mtdname_p );

    return (-EINVAL);
}

static int bcm63xx_write(struct mtd_info *mtd, loff_t to, size_t len,
			size_t *retlen, const u_char *buf)
{
    unsigned long flash_base;
#if !defined(CONFIG_BRCM_IKOS)
    int bytesRemaining = 0;
#endif

    *retlen = 0;
    if ( mtd == (struct mtd_info *)NULL )
    {
        printk("ERROR: bcm63xx_write( mtd[%s])\n", null_mtd_c);
        return (-EINVAL);
    }
    flash_base = (unsigned long)mtd->priv;

#if !defined(CONFIG_BRCM_IKOS)
    bytesRemaining = kerSysWriteToFlash(flash_base+to, (char*)buf, len);
    *retlen = (len - bytesRemaining);
#endif
    return 0;
}

static void bcm63xx_noop(struct mtd_info *mtd)
{
	/* NO OPERATION */
}

/*---------------------------------------------------------------------------
 *	List of Broadcom MTD Devices per supported Flash File Systems
 *
 * - Non WRITEABLE MTD device for the Root FileSystem/kernel
 *   [e.g. the RootFS MTD may host SquashFS]
 * - WRITEABLE MTD device for an Auxillary FileSystem, if configured
 *   [e.g. the AuxFS MTD may host JFFS2]
 *---------------------------------------------------------------------------*/

static struct mtd_info mtdRootFS =
{
	.name		= "BCM63XX RootFS",
	.index		= -1,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= 0,/* No capability: i.e. CLEAR/SET BITS, ERASEABLE */
	.size		= 0,
	.erasesize	= 0,				/* NO ERASE */
	.writesize       = 1,
	.numeraseregions= 0,
	.eraseregions	= (struct mtd_erase_region_info*) NULL,
	//.bank_size	= 2,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase_invalid,	/* READONLY */
	.write		= bcm63xx_write_invalid,	/* READONLY */
	//.point		= bcm63xx_point_invalid,	/* No XIP */
	//.unpoint	= bcm63xx_unpoint_invalid,	/* No XIP */
	.sync		= bcm63xx_noop,
	// NAND Flash Devices not supported: ecc, oob, kvec read/write
	.priv		= (void*) NULL,
	.owner		= THIS_MODULE
};

#ifdef CONFIG_AUXFS_JFFS2
struct mtd_erase_region_info merAuxFS =
{
	.offset = 0,
	.erasesize = 0,
	.numblocks = 0
};

static struct mtd_info mtdAuxFS =
{
	.name		= "BCM63XX AuxFS",
	.index		= -1,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, /* MTD_CLEAR_BITS | MTD_ERASEABLE */
				/* No SET_BITS, WRITEB_WRITEABLE, MTD_OOB */
	.numeraseregions= 1,
	.eraseregions	= (struct mtd_erase_region_info*) &merAuxFS,
	.writesize       = 1,
	//.bank_size	= 2,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	// .point		= bcm63xx_point_invalid,	/* No XIP */
	// .unpoint	= bcm63xx_unpoint_invalid,	/* No XIP */
	.sync		= bcm63xx_noop,
	// NAND Flash Devices not supported: ecc, oob, kvec read/write
	.priv		= (void*) NULL,
	.owner		= THIS_MODULE
};
#endif



struct mtd_erase_region_info mercfeFS =
{
	.offset = 0,
	.erasesize = 0x10000,
	.numblocks = 1
};
static struct mtd_info mtdcfeFS =
{
	.name		= "BCM63XX CFE",
	.index		= -1,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, /* MTD_CLEAR_BITS | MTD_ERASEABLE */
				/* No SET_BITS, WRITEB_WRITEABLE, MTD_OOB */
	.numeraseregions= 1,
	.eraseregions = (struct mtd_erase_region_info*) &mercfeFS,
	.writesize	= 1,
	.erasesize	= 0x10000,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	.sync		= bcm63xx_noop,
	.priv		= (void*) 0xB8000000,
	.owner		= THIS_MODULE,
	.size		= 0x10000
};

struct mtd_erase_region_info mernvramFS =
{
	.offset = 0,
	.erasesize = 0x10000,
	.numblocks = 3
};
static struct mtd_info mtdnvramFS =
{
	.name		= "BCM63XX NVRAM",
	.index		= 3,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, /* MTD_CLEAR_BITS | MTD_ERASEABLE */
				/* No SET_BITS, WRITEB_WRITEABLE, MTD_OOB */
	.numeraseregions = 1,
	.eraseregions = (struct mtd_erase_region_info*) &mernvramFS,
	.writesize	= -1,
	.erasesize	= 0x10000,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	.sync		= bcm63xx_noop,
	.priv		= (void*) 0xB8010000,
	.owner		= THIS_MODULE,
	.size		= 0x30000
};
/*
struct mtd_erase_region_info merSpare4FS =
{
	.offset = 0,
	.erasesize = 0x10000,
	.numblocks = 0x40
};
static struct mtd_info mtdSpare4FS =
{
	.name		= "BCM63XX Overlay Test",
	.index		= -1,			// not registered
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, // MTD_CLEAR_BITS | MTD_ERASEABLE
				// No SET_BITS, WRITEB_WRITEABLE, MTD_OOB
	.numeraseregions = 1,
	.eraseregions	= (struct mtd_erase_region_info*) &merSpare4FS,
	.writesize	= 1,
	.erasesize	= 0x10000,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	.sync		= bcm63xx_noop,
	.priv		= (void*) 0xB8A60000,
	.owner		= THIS_MODULE,
	.size		= 0x400000,
};
*/
struct mtd_erase_region_info merLastSectFS =
{
	.offset = 0,
	.erasesize = 0x10000,
	.numblocks = 1
};
static struct mtd_info mtdLastSectFS =
{
	.name		= "BCM63XX Last Sector",
	.index		= -1,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, /* MTD_CLEAR_BITS | MTD_ERASEABLE */
				/* No SET_BITS, WRITEB_WRITEABLE, MTD_OOB */
	.numeraseregions = 1,
	.eraseregions = (struct mtd_erase_region_info*) &merLastSectFS,
	.writesize	= 1,
	.erasesize	= 0x10000,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	.sync		= bcm63xx_noop,
	.priv		= (void*) 0xB8FF0000,
	.owner		= THIS_MODULE,
	.size		= 0x10000
};

struct mtd_erase_region_info merallFS =
{
	.offset = 0,
	.erasesize = 0x10000,
	.numblocks = 256
};
static struct mtd_info mtdAllFS =
{
	.name		= "BCM63XX All Flash",
	.index		= -1,			/* not registered */
	.type		= MTD_NORFLASH,
	.flags		= MTD_CAP_NORFLASH, /* MTD_CLEAR_BITS | MTD_ERASEABLE */
				/* No SET_BITS, WRITEB_WRITEABLE, MTD_OOB */
	.numeraseregions = 1,
	.eraseregions	= (struct mtd_erase_region_info*) &merallFS,
	.writesize	= 1,
	.erasesize	= 0x10000, // 16777216,
	.read		= bcm63xx_read,
	.erase		= bcm63xx_erase,
	.write		= bcm63xx_write, 
	.sync		= bcm63xx_noop,
	.priv		= (void*) 0xB8000000,
	.owner		= THIS_MODULE,
	.size		= 16777216,
};




static int __init init_brcm_physmap(void)
{
     unsigned int rootfs_addr, kernel_addr, kernel_len, auxfs_addr;
	PFILE_TAG pTag = (PFILE_TAG)NULL;

#ifdef CONFIG_AUXFS_JFFS2
	FLASH_PARTITION_INFO fPartAuxFS;	/* Runtime partitioning info */
#endif

	printk("bcm963xx_mtd driver v%s\n", BCM_MTD_VERSION);

	/*
	 * Data fill the runtime configuration of MTD RootFS Flash Device
	 */
	if (! (pTag = kerSysImageTagGet()) )
	{
                printk("Failed to read image tag from flash\n");
                return -EIO;
        }

	rootfs_addr = (unsigned int) 
		simple_strtoul(pTag->rootfsAddress, NULL, 10)
		+ BOOT_OFFSET;
        kernel_addr = (unsigned int)
		simple_strtoul(pTag->kernelAddress, NULL, 10)
		+ BOOT_OFFSET;
	if ((mtdRootFS.size = (kernel_addr - rootfs_addr)) <= 0)
	{
		printk("Invalid RootFs size\n");
		return -EIO;
	}
	
	/*
	 * CAUTION:
	 * rootfs_addr is NOT ALIGNED WITH a sector boundary.
	 * As, RootFS MTD is not writeable and not explicit erase capability
	 * this is not an issue.
	 * Support for writeable RootFS mtd would need to take into account
	 * the offset of rootfs_addr from the sector base.
	 */
	mtdRootFS.priv = (void*)rootfs_addr;

	if ( add_mtd_device( &mtdRootFS ) )	/* Register Device RootFS */
	{
		printk("Failed to register device mtd[%s]\n", mtdRootFS.name);
		return -EIO;
	}

	printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
		mtdRootFS.name, mtdRootFS.index,
		(int)mtdRootFS.priv, mtdRootFS.size);


#ifdef CONFIG_AUXFS_JFFS2
	/*
	 * Data fill the runtime configuration of MTD AuxFS Flash Device
	 */
	/* Read the flash memory partition map. */
	kerSysFlashPartInfoGet(& fPartAuxFS );

	/*
	 * Assuming a single eraseregion with all sectors of the same size!!!
	 */
	 /*
	if ( fPartAuxFS.sect_size != 0 ) // Check assumption
	{
		mtdAuxFS.priv = (void*)fPartAuxFS.mem_base;
		mtdAuxFS.size = fPartAuxFS.mem_length;

		mtdAuxFS.erasesize = fPartAuxFS.sect_size;

		mtdAuxFS.numeraseregions = 1;
		mtdAuxFS.eraseregions->offset = 0;
		mtdAuxFS.eraseregions->erasesize = fPartAuxFS.sect_size;
		mtdAuxFS.eraseregions->numblocks = fPartAuxFS.number_blk;

		if ( add_mtd_device( & mtdAuxFS ) ) //Register Device AuxFS
		{
			printk("Failed to register device mtd[%s]\n",
				 mtdAuxFS.name);
		return -EIO;
	}	
	
		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdAuxFS.name, mtdAuxFS.index,
			(int)mtdAuxFS.priv, mtdAuxFS.size);

	}
	*/

		/* Replacement AuxFS Details */

        kernel_len = (unsigned int) simple_strtoul(pTag->kernelLen, NULL, 10);

		auxfs_addr  = kernel_addr + kernel_len + 0xFFFF;	// Round up Block
		auxfs_addr /= 0x10000;	// Integer divide
		auxfs_addr *= 0x10000;
		mtdAuxFS.priv  = (void*) auxfs_addr;

		//mtdAuxFS.priv = (void*) kernel_addr + kernel_len; // 0xB8000000 +
		mtdAuxFS.size = 0xB9000000 - auxfs_addr - 0x10000;
		mtdAuxFS.erasesize = 0x10000;

		mtdAuxFS.numeraseregions = 1;
		mtdAuxFS.eraseregions->offset = 0;
		mtdAuxFS.eraseregions->erasesize = 0x10000;
		mtdAuxFS.eraseregions->numblocks = mtdAuxFS.size / 0x10000;

		if ( add_mtd_device( & mtdAuxFS ) )	// Register Device AuxFS
		{
			printk("Failed to register device mtd[%s]\n",
				 mtdAuxFS.name);
			return -EIO;
		}	

		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdAuxFS.name, mtdAuxFS.index,
			(int)mtdAuxFS.priv, mtdAuxFS.size);

#endif


		if ( add_mtd_device( &mtdcfeFS ) ) {
			printk("Failed to register device mtd[%s]\n", mtdcfeFS.name);
			return -EIO;
		}
		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdcfeFS.name, mtdcfeFS.index, (int)mtdcfeFS.priv, mtdcfeFS.size);

		if ( add_mtd_device( &mtdnvramFS ) ) {
			printk("Failed to register device mtd[%s]\n", mtdnvramFS.name);
			return -EIO;
		}
		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdnvramFS.name, mtdnvramFS.index, (int)mtdnvramFS.priv, mtdnvramFS.size);

		if ( add_mtd_device( &mtdLastSectFS ) ) {
			printk("Failed to register device mtd[%s]\n", mtdLastSectFS.name);
			return -EIO;
		}
		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdLastSectFS.name, mtdLastSectFS.index, (int)mtdLastSectFS.priv, mtdLastSectFS.size);

		if ( add_mtd_device( &mtdAllFS ) ) {
			printk("Failed to register device mtd[%s]\n", mtdAllFS.name);
			return -EIO;
		}
		printk("Registered device mtd[%s] dev[%d] Flash[0x%08x,%llu]\n",
			mtdAllFS.name, mtdAllFS.index, (int)mtdAllFS.priv, mtdAllFS.size);


		return 0;
	}

static void __exit cleanup_brcm_physmap(void)
{
	if (mtdRootFS.index >= 0)
	{
		mtdRootFS.index = -1;

		del_mtd_device( &mtdRootFS );

        	mtdRootFS.size = 0;
		mtdRootFS.priv = (void*)NULL;
}

#ifdef CONFIG_AUXFS_JFFS2
	if (mtdAuxFS.index >= 0)
{
		mtdAuxFS.index = -1;

		del_mtd_device( &mtdAuxFS );

		mtdAuxFS.size = 0;
		mtdAuxFS.priv = (void*)NULL;
		mtdAuxFS.erasesize = 0;
		mtdAuxFS.numeraseregions = 0;
		mtdAuxFS.eraseregions->offset = 0;
		mtdAuxFS.eraseregions->erasesize = 0;
		mtdAuxFS.eraseregions->numblocks = 0;
	}
#endif
}

module_init(init_brcm_physmap);
module_exit(cleanup_brcm_physmap);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Song Wang songw@broadcom.com");
MODULE_DESCRIPTION("Configurable MTD Driver for Broadcom Flash File System");
