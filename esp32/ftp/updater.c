/*
 * Copyright (c) 2020, Pycom Limited.
 *
 * This software is licensed under the GNU GPL version 3 or any
 * later version, with permitted additional terms. For more information
 * see the Pycom Licence v1.0 document supplied with this file, or
 * available at https://www.pycom.io/opensource/licensing
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "py/mpconfig.h"
#include "py/obj.h"
#include "bootloader.h"
#include "updater.h"
#include "esp_spi_flash.h"
#include "esp_flash_encrypt.h"
#include "esp_image_format.h"
//#define LOG_LOCAL_LEVEL ESP_LOG_INFO
#include "esp_log.h"
#include "rom/crc.h"
#include "esp32chipinfo.h"

#ifdef DELTA_UPDATE_ENABLED
#include <bzlib.h>
#include "bsdiff_api.h"
#endif

/******************************************************************************
 DEFINE PRIVATE CONSTANTS
 ******************************************************************************/
static const char *TAG = "updater";
#define UPDATER_IMG_PATH                                "/flash/sys/appimg.bin"

/* if flash is encrypted, it requires the flash_write operation to be done in 16 Bytes chunks */
#define ENCRYP_FLASH_MIN_CHUNK                            16

/******************************************************************************
 DEFINE TYPES
 ******************************************************************************/
typedef struct {
    uint32_t size;
    uint32_t offset;
    uint32_t offset_start_upd;
    uint32_t chunk_size;
    uint32_t current_chunk;
} updater_data_t;

/******************************************************************************
 DECLARE PRIVATE DATA
 ******************************************************************************/
static updater_data_t updater_data = {
    .size = 0,
    .offset = 0,
    .offset_start_upd = 0,
    .chunk_size = 0,
    .current_chunk = 0 };

//static OsiLockObj_t updater_LockObj;
static boot_info_t boot_info;
static uint32_t boot_info_offset;

/******************************************************************************
 DECLARE PRIVATE FUNCTIONS
 ******************************************************************************/
static esp_err_t updater_spi_flash_read(size_t src, void *dest, size_t size, bool allow_decrypt);
static esp_err_t updater_spi_flash_write(size_t dest_addr, void *src, size_t size, bool write_encrypted);
#ifdef DELTA_UPDATE_ENABLED
static bool updater_is_delta_file(void);
#endif

/******************************************************************************
 DEFINE PUBLIC FUNCTIONS
 ******************************************************************************/

bool updater_read_boot_info (boot_info_t *boot_info, uint32_t *boot_info_offset) {
    esp_partition_info_t partition_info[PARTITIONS_COUNT_4MB];

    uint8_t part_count = (esp32_get_chip_rev() > 0 ? PARTITIONS_COUNT_8MB : PARTITIONS_COUNT_4MB);
    ESP_LOGV(TAG, "Reading boot info\n");

    if (ESP_OK != updater_spi_flash_read(CONFIG_PARTITION_TABLE_OFFSET, (void *)partition_info, (sizeof(esp_partition_info_t) * part_count), true)) {
            ESP_LOGE(TAG, "err1\n");
            return false;
    }
    // get the data from the boot info partition
    ESP_LOGI(TAG, "read data from: 0x%X\n", partition_info[OTA_DATA_INDEX].pos.offset);
    if (ESP_OK != updater_spi_flash_read(partition_info[OTA_DATA_INDEX].pos.offset, (void *)boot_info, sizeof(boot_info_t), true)) {
            ESP_LOGE(TAG, "err2\n");
            return false;
    }
    *boot_info_offset = partition_info[OTA_DATA_INDEX].pos.offset;
    ESP_LOGD(TAG, "off: %d, status:%d, %d\n", *boot_info_offset, boot_info->Status,  boot_info->ActiveImg);
    return true;
}

bool updater_check_path (void *path) {
//    sl_LockObjLock (&updater_LockObj, SL_OS_WAIT_FOREVER);
    if (!strcmp(UPDATER_IMG_PATH, path)) {
        return true;
    }
//        sl_LockObjUnlock (&updater_LockObj);
    return false;
}

bool updater_start (void) {

    updater_data.size = (esp32_get_chip_rev() > 0 ? IMG_SIZE_8MB : IMG_SIZE_4MB);
    // check which one should be the next active image
    updater_data.offset = updater_ota_next_slot_address();

    ESP_LOGD(TAG, "Updating image at offset = 0x%6X\n", updater_data.offset);
    updater_data.offset_start_upd = updater_data.offset;

    // erase the first 2 sectors
    if (ESP_OK != spi_flash_erase_sector(updater_data.offset / SPI_FLASH_SEC_SIZE)) {
        ESP_LOGE(TAG, "Erasing first sector failed!\n");
        return false;
    }
    if (ESP_OK != spi_flash_erase_sector((updater_data.offset + SPI_FLASH_SEC_SIZE) / SPI_FLASH_SEC_SIZE)) {
        ESP_LOGE(TAG, "Erasing second sector failed!\n");
        return false;
    }

    boot_info.size = 0;
    updater_data.current_chunk = 0;

    return true;
}

bool updater_write (uint8_t *buf, uint32_t len) {

    // the actual writing into flash, not-encrypted,
    // because it already came encrypted from OTA server
    if (ESP_OK != updater_spi_flash_write(updater_data.offset, (void *)buf, len, false)) {
        ESP_LOGE(TAG, "SPI flash write failed\n");
        return false;
    }

    updater_data.offset += len;
    updater_data.current_chunk += len;
    boot_info.size += len;

    if (updater_data.current_chunk >= SPI_FLASH_SEC_SIZE) {
        updater_data.current_chunk -= SPI_FLASH_SEC_SIZE;
        // erase the next sector
        if (ESP_OK != spi_flash_erase_sector((updater_data.offset + SPI_FLASH_SEC_SIZE) / SPI_FLASH_SEC_SIZE)) {
            ESP_LOGE(TAG, "Erasing next sector failed!\n");
            return false;
        }
    }
//    sl_LockObjUnlock (&wlan_LockObj);
    return true;
}

#ifdef DELTA_UPDATE_ENABLED
bool updater_patch(void) {
    bool status = false;                    // Status to be returned (true for success, false otherwise)
    unsigned char header[32];

    uint32_t patch_offset;                  // Offset of the patch file in the flash
    uint32_t patch_size;                    // Size of the patch file
    uint32_t old_bin_offset;                // Offset of the old/current binary image in the flash
    uint32_t newsize;
    uint32_t bzctrllen, bzdatalen, xtralen; // Lengths of various blocks in the patch file

    // Since we haven't switched the active partition, the next partition
    // returned by this function will be the one containing the downloaded patch
    // file NOTE: This also reads the BOOT INFO so we don't have to explicitly
    // read it
    patch_offset = updater_ota_next_slot_address();
    patch_size = boot_info.size;            // boot_info.patch_size;

    // Getting the offset of the current image in the flash
    if (boot_info.ActiveImg == IMG_ACT_FACTORY) {
        old_bin_offset = IMG_FACTORY_OFFSET;
    } else {
        old_bin_offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);
    }

    ESP_LOGI(TAG, "UPDATER_PATCH: Old_Offset: %d, Offset: %d, Size: %d, ChunkSize: %d, Chunk: %d\n",
             old_bin_offset, updater_data.offset, updater_data.size, updater_data.chunk_size, updater_data.current_chunk);
    ESP_LOGI(TAG, "UPDATER_PATCH: BootInfoSize: %d, BootInfoActiveImg: %d\n",
             boot_info.size, boot_info.ActiveImg);

    // File format:
    //     0   8   "BSDIFF40"
    //     8   8   X
    //     16  8   Y
    //     24  8   sizeof(newfile)
    //     32  X   bzip2(control block)
    //     32+X    Y   bzip2(diff block)
    //     32+X+Y  ??? bzip2(extra block)
    // with control block a set of triples (x,y,z) meaning "add x bytes
    // from oldfile to x bytes from the diff block; copy y bytes from the
    // extra block; seek forwards in oldfile by z bytes".

    // Reading header of the patch file

    if (ESP_OK != updater_spi_flash_read(patch_offset, header, 32, false)) {
        ESP_LOGE(TAG, "Error while reading patch file header\n");
        goto return_status;
    }

    // Check for appropriate magic
    if (memcmp(header, "BSDIFF40", 8) != 0) {
        ESP_LOGE(TAG, "Invalid header\n");
        goto return_status;
    }

    ESP_LOGI(TAG,"Header Verified\n");

    // Reading lengths from header
    bzctrllen = offtin(header + 8);
    bzdatalen = offtin(header + 16);
    newsize = offtin(header + 24);

    xtralen = patch_size - (32 + bzctrllen + bzdatalen);

    ESP_LOGI(TAG, "UPDATER_PATCH: CtrlLen: %d, DataLen: %d, NewSize: %d, ExtraLen: %d\n", bzctrllen, bzdatalen, newsize, xtralen);

    if ((bzctrllen < 0) || (bzdatalen < 0) || (newsize < 0) || (xtralen < 0)) {
        ESP_LOGE(TAG, "Invalid Block Sizes\n");
        goto return_status;
    } else {
        const int IN_SIZE = 150 * 1024;             // Max Size of the input buffer for decompression
        const int CTRL_SIZE = 200 * 1024;           // Max Size of the buffer for decompressed Control Block
        const int DIFF_SIZE = 1.8 * 1024 * 1024;    // Max Size of the buffer for decompressed Diff Block
        const int XTRA_SIZE = 200 * 1024;           // Max Size of the buffer for decompressed Extra Block
        const int OLD_BIN_BUF_SIZE = 256;           // Max Size of the buffer for reading chunks of old binary

        uint16_t i = 0;
        unsigned char *in_buf = NULL;
        unsigned char *ctrl_buf = NULL, *ctrl_ptr = NULL;
        unsigned char *diff_buf = NULL, *diff_ptr = NULL;
        unsigned char *xtra_buf = NULL, *xtra_ptr = NULL;
        unsigned char *old_bin_buf = NULL;          // Pointer to read parts of old binary

        int ctrl[3];                                // Buffer to read control block values from the patch file(NOTE: It can be negative)
        int oldpos = 0;                             // Read pointer for old binary
        int newpos = 0;                             // Read pointer for the patched binary

        unsigned int ctrl_len = CTRL_SIZE, diff_len = DIFF_SIZE, xtra_len = XTRA_SIZE;
        int ret = 0;

        ESP_LOGD(TAG, "UPDATER_PATCH: Going to allocate memory for in buffer: %d\n", IN_SIZE);

        in_buf = heap_caps_malloc(IN_SIZE, MALLOC_CAP_SPIRAM);

        if (in_buf == NULL) {
            ESP_LOGE(TAG, "IN Buffer allocation failed\n");
            goto free_mem_and_ret;
        }

        ESP_LOGD(TAG, "UPDATER_PATCH: Going to allocate memory for CTRL buffer: %d\n", CTRL_SIZE);
        ctrl_ptr = ctrl_buf = heap_caps_malloc(CTRL_SIZE, MALLOC_CAP_SPIRAM);

        if (ctrl_buf == NULL) {
            ESP_LOGE(TAG, "CTRL Buffer allocation failed\n");
            goto free_mem_and_ret;
        }

        ESP_LOGD(TAG, "UPDATER_PATCH: Going to allocate memory for DIFF buffer: %d\n", DIFF_SIZE);

        diff_ptr = diff_buf = heap_caps_malloc(DIFF_SIZE, MALLOC_CAP_SPIRAM);

        if (diff_buf == NULL) {
            ESP_LOGE(TAG, "DIFF Buffer allocation failed\n");
            goto free_mem_and_ret;
        }

        ESP_LOGD(TAG, "UPDATER_PATCH: Going to allocate memory for XTRA buffer: %d, XtraLen: %d\n", XTRA_SIZE, xtralen);

        xtra_ptr = xtra_buf = heap_caps_malloc(XTRA_SIZE, MALLOC_CAP_SPIRAM);

        if (xtra_ptr == NULL) {
            ESP_LOGE(TAG, "XTRA Buffer allocation failed\n");
            goto free_mem_and_ret;
        }

        if (bzctrllen > IN_SIZE) {
            ESP_LOGE(TAG, "Ctrl Block length greater than %d\n", IN_SIZE);
            goto free_mem_and_ret;
        }

        // Reading the Control Block from the flash
        if (ESP_OK != updater_spi_flash_read(patch_offset + 32, in_buf, bzctrllen, false)) {
            ESP_LOGE(TAG, "Error while reading control block\n");
            goto free_mem_and_ret;
        }

        ret = BZ2_bzBuffToBuffDecompress((char *)ctrl_buf, &ctrl_len, (char *)in_buf, bzctrllen, 1, 4);

        if (BZ_OK == ret) {
            ESP_LOGD(TAG, "UPDATER_PATCH: Control Block Decompressed. Length: %d --> %d\n", bzctrllen, ctrl_len);
        } else {
            ESP_LOGE(TAG, "UPDATER_PATCH: Control Block Decompression FAILED. Error Code: %d\n", ret);
            goto free_mem_and_ret;
        }

        if (bzdatalen > IN_SIZE) {
            ESP_LOGE(TAG, "UPDATER_PATCH: Data Block length greater than %d\n", IN_SIZE);
            goto free_mem_and_ret;
        }

        // Reading Diff Data Block from the flash
        if (ESP_OK != updater_spi_flash_read(patch_offset + bzctrllen + 32, in_buf, bzdatalen, false)) {
            ESP_LOGE(TAG, "Error while reading diff block\n");
            goto free_mem_and_ret;
        }

        ret = BZ2_bzBuffToBuffDecompress((char *)diff_buf, &diff_len, (char *)in_buf, bzdatalen, 1, 4);

        if (BZ_OK == ret) {
            ESP_LOGD(TAG, "UPDATER_PATCH: Data Block Decompressed. Length: %d --> %d\n", bzdatalen, diff_len);
        } else {
            ESP_LOGE(TAG, "UPDATER_PATCH: Data Block Decompression FAILED. Error Code: %d, OutputBufLen: %d\n", ret, diff_len);
            goto free_mem_and_ret;
        }

        // Decompressing EXTRA BYTES Block
        if (xtralen > IN_SIZE) {
            ESP_LOGE(TAG, "UPDATER_PATCH: Xtra Block length greater than %d\n", IN_SIZE);
            goto free_mem_and_ret;
        }

        // Reading Extra Bytes Block from the flash
        if (ESP_OK != updater_spi_flash_read(patch_offset + 32 + bzctrllen + bzdatalen, in_buf, xtralen, false)) {
            ESP_LOGE(TAG, "Error while reading extra block\n");
            goto free_mem_and_ret;
        }

        ret = BZ2_bzBuffToBuffDecompress((char *)xtra_buf, &xtra_len, (char *)in_buf, xtralen, 1, 4);

        if (BZ_OK == ret) {
            ESP_LOGD(TAG, "UPDATER_PATCH: Extra Block Decompressed. Length: %d --> %d\n", xtralen, xtra_len);
        } else {
            ESP_LOGE(TAG, "UPDATER_PATCH: Extra Block Decompression FAILED. Error Code: %d\n", ret);
            goto free_mem_and_ret;
        }

        // Starting the patching

        // Initializing the parameters of the updater so that the next write is
        // done from the start of the partition
        if (!updater_start()) {
            ESP_LOGE(TAG, "Failed to START UPDATER\n");
            goto free_mem_and_ret;
        }

        old_bin_buf = heap_caps_malloc(OLD_BIN_BUF_SIZE, MALLOC_CAP_SPIRAM);

        if (old_bin_buf == NULL) {
            ESP_LOGE(TAG, "PATCHING: OLD BIN BUF allocation failed. %d bytes were required\n", OLD_BIN_BUF_SIZE);
            goto free_mem_and_ret;
        }

        ESP_LOGD(TAG, "PATCHING: OLD BIN BUF Allocated. Size: %d\n", OLD_BIN_BUF_SIZE);

        while (newpos < newsize) {
            unsigned int byte_count = 0;

            // Reading the control data
            for (i = 0; i <= 2; i++) {
                if ((ctrl_ptr + 8 - ctrl_buf) > ctrl_len) {
                    ESP_LOGE(TAG, "PATCHING: Corrupt Patch. Violated ctrl_len: %d\n", ctrl_len);
                    goto free_mem_and_ret;
                }

                ctrl[i] = offtin(ctrl_ptr);
                ctrl_ptr += 8;
            }

            // Sanity-check
            if (newpos + ctrl[0] > newsize) {
                ESP_LOGE(TAG, "PATCHING: Corrupt Patch. Violated newsize: %d\n", newsize);
                goto free_mem_and_ret;
            }

            // Reading old binary file in chunks combining it with the Diff
            // bytes
            do {
                int bytes_to_read = 0;

                if ((ctrl[0] - byte_count) > OLD_BIN_BUF_SIZE) {
                    bytes_to_read = OLD_BIN_BUF_SIZE;
                } else {
                    bytes_to_read = ctrl[0] - byte_count;
                }

                if (ESP_OK != updater_spi_flash_read(old_bin_offset + oldpos, old_bin_buf, bytes_to_read, false)) {
                    ESP_LOGE(TAG, "Error while reading old bin block\n");
                    goto free_mem_and_ret;
                }

                for (i = 0; i < bytes_to_read; i++) {
                    *(diff_ptr + i) += old_bin_buf[i];
                }

                updater_write(diff_ptr, bytes_to_read);

                diff_ptr += bytes_to_read;
                oldpos += bytes_to_read;
                newpos += bytes_to_read;
                byte_count += bytes_to_read;

            } while (byte_count < ctrl[0]);

            // Sanity-check
            if (newpos + ctrl[1] > newsize) {
                ESP_LOGE(TAG, "PATCHING: Corrupt patch, ctrl[1]: %d violated newsize: %d\n", (int)ctrl[1], (int)newsize);
                goto free_mem_and_ret;
            }

            if (!updater_write(xtra_ptr, ctrl[1])) {
                ESP_LOGE(TAG, "Failed to write buffer of len %d to Flash\n", ctrl[1]);
                goto free_mem_and_ret;
            }

            // Adjust the pointers
            xtra_ptr += ctrl[1];
            newpos += ctrl[1];
            oldpos += ctrl[2];
        }

        ESP_LOGI(TAG, "UPDATER_PATCH: PATCHED: %10d sized file\n", (int)newpos);

        ESP_LOGD(TAG, "UPDATER_PATCH: Old_Offset: %d, Offset: %d, Size: %d, ChunkSize: %d, Chunk: %d\n",
               old_bin_offset, updater_data.offset, updater_data.size,
               updater_data.chunk_size, updater_data.current_chunk);

        status = true;

    free_mem_and_ret:
        heap_caps_free(old_bin_buf);
        heap_caps_free(ctrl_buf);
        heap_caps_free(diff_buf);
        heap_caps_free(in_buf);
    }

return_status:
    if (status) {
        // Updating BOOT INFO
        boot_info.PrevImg = boot_info.ActiveImg;

        if (boot_info.ActiveImg == IMG_ACT_UPDATE1) {
            boot_info.ActiveImg = IMG_ACT_UPDATE2;
        } else {
            boot_info.ActiveImg = IMG_ACT_UPDATE1;
        }
        boot_info.Status = IMG_STATUS_CHECK;
    } else {
        // In case of failure we don't change the active image in boot info
        boot_info.Status = IMG_STATUS_CHECK;
    }

    // save the actual boot_info structure to otadata partition
    updater_write_boot_info(&boot_info, boot_info_offset);
    updater_data.offset = 0;

    return status;
}
#endif

bool updater_finish (void) {
    if (updater_data.offset > 0) {
        ESP_LOGI(TAG, "Updater finished, boot status: %d\n", boot_info.Status);
//        sl_LockObjLock (&wlan_LockObj, SL_OS_WAIT_FOREVER);
        // if we still have an image pending for verification, leave the boot info as it is
        if (boot_info.Status != IMG_STATUS_CHECK) {
#ifdef DELTA_UPDATE_ENABLED
            if(updater_is_delta_file()) {
                ESP_LOGI(TAG, "Found delta image, setting the status to PATCH., BOOT_INFO.SIZE: %d\n", boot_info.size);
                printf("Found delta image, setting the status to PATCH., BOOT_INFO.SIZE: %d\n", boot_info.size);
                //boot_info.patch_size = boot_info.size;
                boot_info.Status = IMG_STATUS_PATCH;

                updater_write_boot_info(&boot_info, boot_info_offset);

            }else 
#endif
            {
                ESP_LOGI(TAG, "Saving new boot info\n");
                // save the new boot info
                boot_info.PrevImg = boot_info.ActiveImg;
                if (boot_info.ActiveImg == IMG_ACT_UPDATE1) {
                    boot_info.ActiveImg = IMG_ACT_UPDATE2;
                } else {
                    boot_info.ActiveImg = IMG_ACT_UPDATE1;
                }
                boot_info.Status = IMG_STATUS_CHECK;

                // save the actual boot_info structure to otadata partition
                updater_write_boot_info(&boot_info, boot_info_offset);
            }
        }
//        sl_LockObjUnlock (&wlan_LockObj);
        updater_data.offset = 0;
    }
//    sl_LockObjUnlock (&updater_LockObj);
    return true;
}

bool updater_verify (void) {
    // bootloader verifies anyway the image, but the user can check himself
    // so, the next code is adapted from bootloader/bootloader.c,

    // the last image written stats at updater_data.offset_start_upd and
    // has the lenght boot_info.size

    esp_err_t ret;
    esp_image_metadata_t data;
    const esp_partition_pos_t part_pos = {
      .offset = updater_data.offset_start_upd,
      .size = boot_info.size,
    };

    ret = esp_image_verify(ESP_IMAGE_VERIFY, &part_pos, &data);

    ESP_LOGI(TAG, "esp_image_verify: %d\n", ret);

    return (ret == ESP_OK);
}


bool updater_write_boot_info(boot_info_t *boot_info, uint32_t boot_info_offset) {

    boot_info->crc = crc32_le(UINT32_MAX, (uint8_t *)boot_info, sizeof(boot_info_t) - sizeof(boot_info->crc));
    ESP_LOGI(TAG, "Wr crc=0x%x\n", boot_info->crc);

    if (ESP_OK != spi_flash_erase_sector(boot_info_offset / SPI_FLASH_SEC_SIZE)) {
        printf("Erasing boot info failed\n");
        return false;
    }

    // saving boot info, encrypted
    esp_err_t ret; // return code of the flash_write operation
    if (esp_flash_encryption_enabled()) {
        // sizeof(boot_info_t) is 40 bytes, and we have to write multiple of 16
        // so read next 48-40 bytes from flash, and write back 48 B

        uint32_t len_aligned_16 = ((sizeof(boot_info_t) + 15) / 16) * 16;
        uint8_t *buff; // buffer used for filling boot_info data
        buff = (uint8_t *)malloc(len_aligned_16);

        if (!buff) {
            ESP_LOGE(TAG, "Can't allocate %d\n", len_aligned_16);
            return false;
        }

        // put the first sizeof(boot_info_t)
        memcpy(buff, (void *)boot_info, sizeof(boot_info_t));

        // read the next bytes
        spi_flash_read_encrypted(boot_info_offset + sizeof(boot_info_t),
                                (void *)(buff + sizeof(boot_info_t)),
                                len_aligned_16 - sizeof(boot_info_t) );

        ret = spi_flash_write_encrypted(boot_info_offset, (void *)buff, len_aligned_16);
    } else { // not-encrypted flash, just write directly boot_info
            ret = spi_flash_write(boot_info_offset, (void *)boot_info, sizeof(boot_info_t));
    }

    if (ESP_OK != ret) {
        ESP_LOGE(TAG, "Saving boot info failed\n");
    } else {
            ESP_LOGI(TAG, "Boot info saved OK\n");
    }

    return (ESP_OK == ret);
}

int updater_ota_next_slot_address() {

    int ota_offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);

    // check which one should be the next active image
    if (updater_read_boot_info (&boot_info, &boot_info_offset)) {
        // if we still have an image pending for verification, keep overwriting it
        if (boot_info.Status == IMG_STATUS_CHECK) {
            if(boot_info.ActiveImg == IMG_ACT_FACTORY)

            {
                ota_offset = IMG_FACTORY_OFFSET;
            }
            else
            {
                ota_offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);
            }
        }
        else
        {
            if(boot_info.ActiveImg == IMG_ACT_FACTORY)

            {
                ota_offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);
            }
            else
            {
                ota_offset = IMG_FACTORY_OFFSET;
            }
        }
    }

    ESP_LOGI(TAG, "Next slot address: 0x%6X\n", ota_offset);

    return ota_offset;
}

/******************************************************************************
 DEFINE PRIVATE FUNCTIONS
 ******************************************************************************/

static esp_err_t updater_spi_flash_read(size_t src, void *dest, size_t size, bool allow_decrypt)
{
    if (allow_decrypt && esp_flash_encryption_enabled()) {
        return spi_flash_read_encrypted(src, dest, size);
    } else {
        return spi_flash_read(src, dest, size);
    }
}

/* @note Both dest_addr and size must be multiples of 16 bytes. For
 * absolute best performance, both dest_addr and size arguments should
 * be multiples of 32 bytes.
*/
static esp_err_t updater_spi_flash_write(size_t dest_addr, void *src, size_t size,
                                        bool write_encrypted)
{
    if (write_encrypted && esp_flash_encryption_enabled()) {
        return spi_flash_write_encrypted(dest_addr, src, size);
    } else {
        return spi_flash_write(dest_addr, src, size);
    }
}

#ifdef DELTA_UPDATE_ENABLED
/* @brief Checks whether the image present in the inactive partition a patch
 * file or not.
 */
static bool updater_is_delta_file(void)
{
    unsigned int offset;
    unsigned char header[32] = {0};

    // Basically doing all that updater_ota_next_slot_address() does minus reading the bootinfo since we haven't saved it yet.
    if (boot_info.Status == IMG_STATUS_CHECK)
    {
        if (boot_info.ActiveImg == IMG_ACT_FACTORY)

        {
            offset = IMG_FACTORY_OFFSET;
        }
        else
        {
            offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);
        }
    }
    else
    {
        if (boot_info.ActiveImg == IMG_ACT_FACTORY)

        {
            offset = (esp32_get_chip_rev() > 0 ? IMG_UPDATE1_OFFSET_8MB : IMG_UPDATE1_OFFSET_4MB);
        }
        else
        {
            offset = IMG_FACTORY_OFFSET;
        }
    }

    if(ESP_OK != updater_spi_flash_read(offset, header, 32, false))
    {
        printf("Error while reading patch file header\n");
        ESP_LOGE(TAG, "err1\n");
        return false;
    }

    // Check for appropriate magic
    if (memcmp(header, "BSDIFF40", 8) != 0)
    {
        printf("Header does not match the delta file header. This is not a valid delta file.\n");
        ESP_LOGE(TAG, "Invalid header\n");

        return false;
    }

    return true;
}
#endif