// Required header
#include <ps5/payload_main.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <ps5/libkernel.h>
#include <ps5/kernel.h>

#include "sbl.h"
#include "authmgr.h"
#include "self.h"
#include "elf.h"

#define PC_IP   "10.0.3.3"
#define PC_PORT 5655

struct tailored_offsets
{
    uint64_t offset_dmpml4i;
    uint64_t offset_dmpdpi;
    uint64_t offset_pml4pml4i;
    uint64_t offset_mailbox_base;
    uint64_t offset_mailbox_flags;
    uint64_t offset_mailbox_meta;
    uint64_t offset_authmgr_handle;
    uint64_t offset_sbl_sxlock;
    uint64_t offset_sbl_mb_mtx;
    uint64_t offset_datacave_1;
    uint64_t offset_datacave_2;
};

uint64_t g_kernel_data_base;
char *g_bump_allocator_base;
char *g_bump_allocator_cur;
uint64_t g_bump_allocator_len;
char *g_hexbuf;
char *g_dirent_buf;

void *bump_alloc(uint64_t len)
{
    void *ptr;
    if (g_bump_allocator_cur + len >= (g_bump_allocator_base + g_bump_allocator_len)) {
        return NULL;
    }

    ptr = (void *) g_bump_allocator_cur;
    g_bump_allocator_cur += len;

    // Zero init to avoid stupid bugs
    (void)memset(ptr, 0, len);

    return ptr;
}

void *bump_calloc(uint64_t count, uint64_t len)
{
    uint64_t total_len;

    total_len = count * len;
    return bump_alloc(total_len);
}

void bump_reset()
{
    g_bump_allocator_cur = g_bump_allocator_base;
}

void sock_print(int sock, char *str)
{
	size_t size;

	size = strlen(str);
	_write(sock, str, size);
}

static void _mkdir(const char *dir) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0777);
            *p = '/';
        }
    mkdir(tmp, 0777);
}

uint64_t get_authmgr_sm(int sock, struct tailored_offsets *offsets)
{
    uint64_t authmgr_sm_handle;

    kernel_copyout(g_kernel_data_base + offsets->offset_authmgr_handle, &authmgr_sm_handle, sizeof(authmgr_sm_handle));
    return authmgr_sm_handle;
}

int self_verify_header(int sock, uint64_t authmgr_handle, char *data, uint64_t size, struct tailored_offsets *offsets)
{
    int err;
    uint64_t data_blob_va;
    uint64_t data_blob_pa;

    // Get mailbox physical/virtual address
    data_blob_va   = g_kernel_data_base + offsets->offset_datacave_2;
    data_blob_pa   = pmap_kextract(sock, data_blob_va);

    // Copy header in
    kernel_copyin(data, data_blob_va, size);

    // We must finalize the context to 'reset' it
    err = _sceSblAuthMgrSmFinalize(sock, authmgr_handle, 0);
    if (err != 0)
        return err;

    // Submit request and return service ID
    return _sceSblAuthMgrVerifyHeader(sock, authmgr_handle, data_blob_pa, size);
}

struct self_block_segment *self_decrypt_segment(
    int sock,
    int authmgr_handle,
    int service_id,
    char *file_data,
    struct sce_self_segment_header *segment,
    int segment_idx,
    struct tailored_offsets *offsets)
{
    int err;
    void *out_segment_data;
    void **digests;
    char *cur_digest;
    struct self_block_segment *segment_info;
    struct sce_self_block_info *cur_block_info;
    struct sce_self_block_info **block_infos;
    struct sbl_chunk_table_header *chunk_table;
    struct sbl_chunk_table_entry *chunk_entry;
    uint64_t chunk_table_va;
    uint64_t data_blob_va;
    uint64_t chunk_table_pa;
    uint64_t data_blob_pa;
    char chunk_table_buf[0x1000] = {};

    // Copy segment data into data cave #1
    data_blob_va   = g_kernel_data_base + offsets->offset_datacave_2;
    data_blob_pa   = pmap_kextract(sock, data_blob_va);

    if (segment->compressed_size < 0x1000)
        kernel_copyin(file_data + segment->offset, data_blob_va, segment->compressed_size);
    else {
        for (int bytes = 0; bytes < segment->compressed_size; bytes += 0x1000) {
            if (segment->compressed_size - bytes < 0x1000)
                kernel_copyin(file_data + segment->offset + bytes, data_blob_va + bytes, (segment->compressed_size - bytes));
            else
                kernel_copyin(file_data + segment->offset + bytes, data_blob_va + bytes, 0x1000);
        }
    }

    // Construct chunk table
    chunk_table = (struct sbl_chunk_table_header *) (chunk_table_buf);
    chunk_entry = (struct sbl_chunk_table_entry *) (chunk_table_buf + sizeof(struct sbl_chunk_table_header));

    chunk_table->first_pa = data_blob_pa;
    chunk_table->used_entries = 1;
    chunk_table->data_size = segment->compressed_size;

    chunk_entry->pa = data_blob_pa;
    chunk_entry->size = segment->compressed_size;

    chunk_table_va = g_kernel_data_base + offsets->offset_datacave_1;
    chunk_table_pa = pmap_kextract(sock, chunk_table_va);

    // Copy out chunk table into data cave #2
    kernel_copyin(chunk_table, chunk_table_va, 0x30);

    // Request segment decryption
    for (int tries = 0; tries < 3; tries++) {
        err = _sceSblAuthMgrSmLoadSelfSegment(sock, authmgr_handle, service_id, chunk_table_pa, segment_idx);
        if (err == 0)
            break;
        sceKernelSleep(1);
    }

    if (err != 0)
        return NULL;

    out_segment_data = mmap(NULL, segment->uncompressed_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_segment_data == NULL)
        return NULL;

    // Copy out decrypted content
    kernel_copyout(data_blob_va, out_segment_data, segment->uncompressed_size);

    // Track segment info for use later
    segment_info = bump_alloc(sizeof(struct self_block_segment));
    if (segment_info == NULL)
        return NULL;

    segment_info->data = out_segment_data;
    segment_info->size = segment->uncompressed_size;

    // We can get the block count by dividing the size by 0x28 (0x20 for digest, 0x8 for extent)
    segment_info->block_count = segment_info->size / (0x20 + 0x8);

    // Keep track of block digests
    digests = bump_calloc(segment_info->block_count, sizeof(void *));
    if (digests == NULL)
        return NULL;

    cur_digest = (char *) out_segment_data;
    for (int i = 0; i < segment_info->block_count; i++) {
        digests[i] = (void *) cur_digest;
        cur_digest += 0x20;
    }

    segment_info->digests = digests;

    // Keep track of block extent information
    block_infos    = bump_calloc(segment_info->block_count, sizeof(struct sce_self_block_info *));
    if (block_infos == NULL)
        return NULL;

    cur_block_info = (struct sce_self_block_info *) (out_segment_data + (0x20 * segment_info->block_count));
    for (int i = 0; i < segment_info->block_count; i++) {
        block_infos[i] = cur_block_info++;
    }

    segment_info->extents = block_infos;
    return segment_info;
}

void *self_decrypt_block(
    int sock,
    int authmgr_handle,
    int service_id,
    char *file_data,
    struct sce_self_segment_header *segment,
    int segment_idx,
    struct self_block_segment *block_segment,
    int block_idx,
    struct tailored_offsets *offsets)
{
    int err;
    uint64_t data_blob_va;
    uint64_t data_out_va;
    uint64_t data_blob_pa;
    uint64_t data_out_pa;
    uint64_t input_addr;
    void *out_block_data;

    data_out_va  = g_kernel_data_base + offsets->offset_datacave_1;
    data_out_pa  = pmap_kextract(sock, data_out_va);

    data_blob_va = g_kernel_data_base + offsets->offset_datacave_2;
    data_blob_pa = pmap_kextract(sock, data_blob_va);

    // Calculate input address and size
    input_addr = (uint64_t) (file_data + segment->offset + block_segment->extents[block_idx]->offset);

    // Segmented copy into data cave #1
    for (int i = 0; i < 4; i++) {
        kernel_copyin((void *) (input_addr + (i * 0x1000)), data_blob_va + (i * 0x1000), 0x1000);
    }

    // Request segment decryption
    for (int tries = 0; tries < 3; tries++) {
        err = _sceSblAuthMgrSmLoadSelfBlock(
            sock,
            authmgr_handle,
            service_id,
            data_blob_pa,
            data_out_pa,
            segment,
            SELF_SEGMENT_ID(segment),
            block_segment,
            block_idx
        );
        if (err == 0)
            break;
        sceKernelSleep(1);
    }

    if (err != 0)
        return NULL;

    out_block_data = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_block_data == NULL)
        return NULL;

    // Segmented copy out decrypted content
    for (int i = 0; i < 4; i++) {
        kernel_copyout(data_out_va + (i * 0x1000), out_block_data + (i * 0x1000), 0x1000);
    }

    return out_block_data;
}

int decrypt_self(int sock, uint64_t authmgr_handle, char *path, int out_fd, struct tailored_offsets *offsets)
{
    int err;
    int service_id;
    int written_bytes;
    int self_file_fd;
    struct stat self_file_stat;
    void *self_file_data;
    void *out_file_data;
    struct elf64_hdr *elf_header;
    struct elf64_phdr *start_phdrs;
    struct elf64_phdr *cur_phdr;
    struct sce_self_header *header;
    struct sce_self_segment_header *segment;
    struct sce_self_segment_header *target_segment;
    struct self_block_segment **block_segments;
    struct self_block_segment *block_info;
    void **block_data;
    uint64_t tail_block_size;
    uint64_t final_file_size;

    err = 0;

    // Open SELF file for reading
    self_file_fd = _open(path, 0, 0);
    if (self_file_fd < 0) {
        SOCK_LOG(sock, "[!] failed to open %s\n", path);
        _close(out_fd);
        return self_file_fd;
    }

    _fstat(self_file_fd, &self_file_stat);
    self_file_data = mmap(NULL, self_file_stat.st_size, PROT_READ, MAP_SHARED, self_file_fd, 0);

    if (*(uint32_t *) (self_file_data) != SELF_PROSPERO_MAGIC) {
        SOCK_LOG(sock, "[!] %s is not a PS5 SELF file\n", path);
        err = -22;
        goto cleanup_in_file_data;
    }

    SOCK_LOG(sock, "[+] decrypting %s...\n", path);

    // Verify SELF header and get a context handle
    header = (struct sce_self_header *) self_file_data;
    service_id = self_verify_header(
        sock,
        authmgr_handle,
        self_file_data,
        header->header_size + header->metadata_size,
        offsets);

    if (service_id < 0) {
        SOCK_LOG(sock, "[!] failed to acquire a service ID\n");
        err = -1;
        goto cleanup_in_file_data;
    }

    // Get ELF headers
    elf_header  = (struct elf64_hdr *) (self_file_data + sizeof(struct sce_self_header) +
                    (sizeof(struct sce_self_segment_header) * header->segment_count));
    start_phdrs = (struct elf64_phdr *) ((char *) (elf_header) + sizeof(struct elf64_hdr));

    // Allocate backing buffer for output file data. We'll get size by finding the NOTE program header which should be
    // in most SELFs
    cur_phdr = start_phdrs;
    final_file_size = 0;
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (cur_phdr->p_type == PT_NOTE)
            final_file_size = cur_phdr->p_offset + cur_phdr->p_filesz;
        cur_phdr++;
    }

    if (final_file_size == 0) {
        // Second chance: fallback on latest LOAD segment size
        SOCK_LOG(sock, "  [?] file segments are irregular, falling back on last LOAD segment\n");

        cur_phdr = start_phdrs;
        for (int i = 0; i < elf_header->e_phnum; i++) {
            if (cur_phdr->p_type == PT_LOAD)
                final_file_size = cur_phdr->p_offset + cur_phdr->p_filesz;
            cur_phdr++;
        }
    }

    out_file_data = mmap(NULL, final_file_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (out_file_data == NULL || out_file_data == -1) {
        err = -12;
        goto cleanup_in_file_data;
    }

    // Copy ELF headers over
    memcpy(out_file_data, elf_header, sizeof(struct elf64_hdr));
    memcpy(out_file_data + sizeof(struct elf64_hdr), start_phdrs, elf_header->e_phnum * sizeof(struct elf64_phdr));

    // Digest
    memcpy(
        out_file_data + sizeof(struct elf64_hdr) + (elf_header->e_phnum * sizeof(struct elf64_phdr)),
        (char *) (start_phdrs) + (elf_header->e_phnum * sizeof(struct elf64_phdr)),
        0x40
    );

    // Allocate array to hold block info
    block_segments = bump_calloc(header->segment_count, sizeof(struct self_block_segment *));
    if (block_segments == NULL) {
        err = -12;
        goto cleanup_out_file_data;
    }

    // Decrypt block info segments
    for (int i = 0; i < header->segment_count; i++) {
        segment = (struct sce_self_segment_header *) (self_file_data +
                sizeof(struct sce_self_header) + (i * sizeof(struct sce_self_segment_header)));

        if (SELF_SEGMENT_HAS_DIGESTS(segment)) {
            target_segment = (struct sce_self_segment_header *) (self_file_data +
                sizeof(struct sce_self_header) + (SELF_SEGMENT_ID(segment) * sizeof(struct sce_self_segment_header)));
            SOCK_LOG(sock, "  [?] decrypting block info segment for %d\n", SELF_SEGMENT_ID(target_segment));
            block_segments[SELF_SEGMENT_ID(segment)] = self_decrypt_segment(
                sock,
                authmgr_handle,
                service_id,
                self_file_data,
                segment,
                SELF_SEGMENT_ID(target_segment),
                offsets
            );

            if (block_segments[SELF_SEGMENT_ID(segment)] == NULL) {
                SOCK_LOG(sock, "[!] failed to decrypt segment info for segment %d\n", SELF_SEGMENT_ID(segment));
                err = -11;
                goto cleanup_out_file_data;
            }
        }
    }

    /*for (int i = 0; i < header->segment_count; i++) {
        if (block_segments[i]) {
            SOCK_LOG(sock, "decrypted info segment for seg=0x%02x (%d blocks)\n", i, block_segments[i]->block_count);

            for (int j = 0; j < block_segments[i]->block_count; j++) {
                SOCK_LOG(sock, "  block #%04d, extent (offset: 0x%08x, len: 0x%08x), digest:\n",
                         j,
                         block_segments[i]->extents[j]->offset,
                         block_segments[i]->extents[j]->len);
                DumpHex(sock, (block_segments[i]->data + (j * 0x20)), 0x20);
            }
        }
    }*/

    // Decrypt regular blocked-segments to file
    for (int i = 0; i < header->segment_count; i++) {
        segment = (struct sce_self_segment_header *) (self_file_data +
                sizeof(struct sce_self_header) + (i * sizeof(struct sce_self_segment_header)));

        // Ignore info and non-blocked segments
        if (!SELF_SEGMENT_HAS_BLOCKS(segment) || SELF_SEGMENT_HAS_DIGESTS(segment)) {
            continue;
        }

        // Get accompanying ELF segment
        cur_phdr = start_phdrs;
        for (int phnum = 0; phnum < header->segment_count; phnum++) {
            if (cur_phdr->p_filesz == segment->uncompressed_size)
                break;
            cur_phdr++;
        }

        // Get block info for this segment
        block_info = block_segments[i];
        if (block_info == NULL) {
            SOCK_LOG(sock, "[!] we don't have block info for segment %d\n", i);
            continue;
        }

        // Allocate array to hold decrypted block data
        block_data = bump_calloc(block_info->block_count, sizeof(void *));
        if (block_data == NULL) {
            err = -12;
            goto cleanup_out_file_data;
        }

        // Get tail block size
        tail_block_size = segment->uncompressed_size % SELF_SEGMENT_BLOCK_SIZE(segment);

        for (int block = 0; block < block_info->block_count; block++) {
            SOCK_LOG(sock, "  [?] decrypting segment=%d, block=%d/%d\n", i, block + 1, block_info->block_count);
            block_data[block] = self_decrypt_block(
                sock,
                authmgr_handle,
                service_id,
                self_file_data,
                segment,
                i,
                block_info,
                block,
                offsets
            );

            if (block_data[block] == NULL) {
                SOCK_LOG(sock, "[!] failed to decrypt block %d\n", block);
                err = -11;
                goto cleanup_out_file_data;
            }

            // Copy block to output buffer
            void *out_addr = out_file_data + cur_phdr->p_offset + (block * SELF_SEGMENT_BLOCK_SIZE(segment));

            if (block == block_info->block_count - 1) {
                // Last block, truncate size
                memcpy(out_addr, block_data[block], tail_block_size);
            } else {
                memcpy(out_addr, block_data[block], SELF_SEGMENT_BLOCK_SIZE(segment));
            }

            munmap(block_data[block], SELF_SEGMENT_BLOCK_SIZE(segment));
        }
    }

    written_bytes = _write(out_fd, out_file_data, final_file_size);
    if (written_bytes != final_file_size) {
        SOCK_LOG(sock, "[!] failed to dump to file, %d != %d (%d).\n", written_bytes, final_file_size, errno);
        err = -5;
    }

    SOCK_LOG(sock, "  [+] wrote 0x%08x bytes...\n", written_bytes);

cleanup_out_file_data:
    munmap(out_file_data, final_file_size);
cleanup_in_file_data:
    munmap(self_file_data, self_file_stat.st_size);
    _close(self_file_fd);
    _close(out_fd);

    // Reset the bump allocator
    bump_reset();

    return err;
}

void preload_dirents(int sock, char *dir, char *out)
{
    int dir_fd;

    // Walk the directory and find entries
    dir_fd = sceKernelOpen(dir, O_RDONLY, 0);
    if (dir_fd < 0) {
        SOCK_LOG(sock, "[!] failed to open directory\n");
        return;
    }
    SOCK_LOG(sock, "[?] dirfd = %d\n", dir_fd);

    if (sceKernelGetdents(dir_fd, out, 0x10000) < 0) {
        SOCK_LOG(sock, "[!] failed to get directory entries (%d)\n", errno);
        sceKernelClose(dir_fd);
        return;
    }

    sceKernelClose(dir_fd);
}

void dump_dir(int sock, uint64_t authmgr_handle, struct tailored_offsets *offsets, char *dents, char *dir, char *out_dir_path)
{
    int err;
    int out_fd;
    struct dirent *entry;
    char in_file_path[256];
    char out_file_path[256];
    struct stat out_file_stat;
    uint64_t spinlock_lock = 0x13371337;

    SOCK_LOG(sock, "[+] dumping %s...\n", dir);

    // Make output directory just in case
    _mkdir(out_dir_path);

    // Lock the SBL spinlock BKL style
    for (int i = 0; i < 0x100; i++) {
        kernel_copyin(&spinlock_lock, g_kernel_data_base + offsets->offset_sbl_sxlock + 0x18, 0x8);
        sceKernelUsleep(1000);
    }

    entry = (struct dirent *) dents;
    while (entry->d_fileno) {
        if (entry->d_type == DT_REG) {
            sprintf((char *) &in_file_path, "%s/%s", dir, entry->d_name);
            sprintf((char *) &out_file_path, "%s/%s", out_dir_path, entry->d_name);

            // Check if output file already exists and is non-zero size, if so skip it
            out_fd = _open(out_file_path, O_RDONLY, 0);
            if (out_fd >= 0) {
                _fstat(out_fd, &out_file_stat);
                _close(out_fd);
                if (out_file_stat.st_size > 0) {
                    entry = (struct dirent *) ((char *) entry + entry->d_reclen);
                    continue;
                }
            }

//            for (int i = 0; i < 0x100; i++) {
//                kernel_copyin(&spinlock_lock, g_kernel_data_base + offsets->offset_sbl_sxlock + 0x18, 0x8);
//                sceKernelUsleep(100);
//            }

            // Decrypt
            out_fd = _open(out_file_path, O_WRONLY | O_CREAT, 0644);
            err = decrypt_self(sock, authmgr_handle, in_file_path, out_fd, offsets);
            if (err == -11) {
                // Give 2 more attempts
                for (int attempt = 0; attempt < 2; attempt++) {
                    out_fd = _open(out_file_path, O_WRONLY | O_CREAT, 0644);
                    err = decrypt_self(sock, authmgr_handle, in_file_path, out_fd, offsets);
                    if (err == 0)
                        break;
                }
            }

            if (err != 0) {
                sceKernelUnlink(out_file_path);
            }

            if (err == -5) {
                goto out;
            }
        }

        entry = (struct dirent *) ((char *) entry + entry->d_reclen);
    }

out:
    // Unlock SBL spinlock
    spinlock_lock = 0x0;
    kernel_copyin(&spinlock_lock, g_kernel_data_base + offsets->offset_sbl_sxlock + 0x18, 0x8);

    if (err == -5) {
        SOCK_LOG(sock, "[!] skipping rest of directory due to failed write\n");
    } else {
        SOCK_LOG(sock, "[+] completed directory\n");
    }
}

int payload_main(struct payload_args *args)
{
	int ret;
	int sock;
	struct sockaddr_in addr;
    uint64_t authmgr_handle;
    struct OrbisKernelSwVersion version;
    struct tailored_offsets offsets;

	// Open a debug socket to log to PC
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return -1;
	}

	inet_pton(AF_INET, PC_IP, &addr.sin_addr);
	addr.sin_family = AF_INET;
	addr.sin_len    = sizeof(addr);
	addr.sin_port   = htons(PC_PORT);

	ret = connect(sock, (const struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		return -1;
	}

    // Initialize dump hex area
    g_hexbuf = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_hexbuf == NULL) {
        SOCK_LOG(sock, "[!] failed to allocate hex dump area\n");
        goto out;
    }

    // Initialize bump allocator
    g_bump_allocator_len  = 0x100000;
    g_bump_allocator_base = mmap(NULL, g_bump_allocator_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_bump_allocator_base == NULL) {
        SOCK_LOG(sock, "[!] failed to allocate backing space for bump allocator\n");
        goto out;
    }

    g_bump_allocator_cur = g_bump_allocator_base;

    // Initialize dirent buffer
    g_dirent_buf = mmap(NULL, 6 * 0x10000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_dirent_buf == NULL || g_dirent_buf == -1) {
        SOCK_LOG(sock, "[!] failed to allocate buffer for directory entries\n");
        goto out;
    }

	// Print basic info
    SOCK_LOG(sock, "[+] kernel .data base is %p, pipe %d->%d, rw pair %d->%d, pipe addr is %p\n",
             args->kdata_base_addr, args->rwpipe[0], args->rwpipe[1], args->rwpair[0], args->rwpair[1], args->kpipe_addr);

	// Initialize kernel read/write helpers
	kernel_init_rw(args->rwpair[0], args->rwpair[1], args->rwpipe, args->kpipe_addr);
    g_kernel_data_base = args->kdata_base_addr;

    // Tailor
    sceKernelGetProsperoSystemSwVersion(&version);
    SOCK_LOG(sock, "[+] firmware version 0x%x (%s)\n", version.version, version.version_str);

    // See README for porting notes
    switch (version.version) {
    case 0x3000038:
    case 0x3100003:
    case 0x3200004:
    case 0x3210000:
        offsets.offset_authmgr_handle = 0xC9EE50;
        offsets.offset_sbl_mb_mtx     = 0x2712A98;
        offsets.offset_mailbox_base   = 0x2712AA0;
        offsets.offset_sbl_sxlock     = 0x2712AA8;
        offsets.offset_mailbox_flags  = 0x2CF5F98;
        offsets.offset_mailbox_meta   = 0x2CF5D38;
        offsets.offset_dmpml4i        = 0x31BE4A0;
        offsets.offset_dmpdpi         = 0x31BE4A4;
        offsets.offset_pml4pml4i      = 0x31BE1FC;
        offsets.offset_datacave_1     = 0x4270000;
        offsets.offset_datacave_2     = 0x4280000;
        break;
    case 0x4000042:
    case 0x4030000:
    case 0x4500005:
    case 0x4510001:
        offsets.offset_authmgr_handle = 0xD0FBB0;
        offsets.offset_sbl_mb_mtx     = 0x2792AB8;
        offsets.offset_mailbox_base   = 0x2792AC0;
        offsets.offset_sbl_sxlock     = 0x2792AC8;
        offsets.offset_mailbox_flags  = 0x2D8DFC0;
        offsets.offset_mailbox_meta   = 0x2D8DD60;
        offsets.offset_dmpml4i        = 0x3257D00;
        offsets.offset_dmpdpi         = 0x3257D04;
        offsets.offset_pml4pml4i      = 0x3257A5C;
        offsets.offset_datacave_1     = 0x4270000;
        offsets.offset_datacave_2     = 0x4280000;
        break;
    default:
        SOCK_LOG(sock, "[!] unsupported firmware, dumping then bailing!\n");
        char *dump_buf = mmap(NULL, 0x7800 * 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        for (int pg = 0; pg < 0x7800; pg++) {
            kernel_copyout(g_kernel_data_base + (pg * 0x1000), dump_buf + (pg * 0x1000), 0x1000);
        }

        int dump_fd = _open("/mnt/usb0/PS5/data_dump.bin", O_WRONLY | O_CREAT, 0644);
        _write(dump_fd, dump_buf, 0x7800 * 0x1000);
        _close(dump_fd);
        SOCK_LOG(sock, "  [+] dumped\n");
        goto out;
    }

    // Initialize SBL offsets
    init_sbl(
        g_kernel_data_base,
        offsets.offset_dmpml4i,
        offsets.offset_dmpdpi,
        offsets.offset_pml4pml4i,
        offsets.offset_mailbox_base,
        offsets.offset_mailbox_flags,
        offsets.offset_mailbox_meta,
        offsets.offset_sbl_mb_mtx);

    authmgr_handle = get_authmgr_sm(sock, &offsets);
    SOCK_LOG(sock, "[+] got auth manager: %p\n", authmgr_handle);

    preload_dirents(sock, "/", g_dirent_buf + (0 * 0x10000));
    preload_dirents(sock, "/system/common/lib", g_dirent_buf + (1 * 0x10000));
    preload_dirents(sock, "/system_ex/common_ex/lib", g_dirent_buf + (2 * 0x10000));
    preload_dirents(sock, "/system/priv/lib", g_dirent_buf + (3 * 0x10000));
    preload_dirents(sock, "/system/sys", g_dirent_buf + (4 * 0x10000));
    preload_dirents(sock, "/system/vsh", g_dirent_buf + (5 * 0x10000));

    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (0 * 0x10000), "/", "/mnt/usb0/PS5");
    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (1 * 0x10000), "/system/common/lib", "/mnt/usb0/PS5/system/common/lib");
    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (2 * 0x10000), "/system_ex/common_ex/lib", "/mnt/usb0/PS5/system_ex/common_ex/lib");
    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (3 * 0x10000), "/system/priv/lib", "/mnt/usb0/PS5/system/priv/lib");
    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (4 * 0x10000), "/system/sys", "/mnt/usb0/PS5/system/sys");
    dump_dir(sock, authmgr_handle, &offsets, g_dirent_buf + (5 * 0x10000), "/system/vsh", "/mnt/usb0/PS5/system/vsh");

    SOCK_LOG(sock, "[+] done!\n");

out:
	_close(sock);
	return 0;
}
