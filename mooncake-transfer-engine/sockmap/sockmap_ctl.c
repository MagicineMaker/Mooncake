// SPDX-License-Identifier: Apache-2.0
// The replay owns an empty, private bpffs directory for the lifetime of its
// pool.
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static const char *const maps[] = {"client_socks", "server_socks"};
static const char *const programs[] = {"from_client", "from_server"};

static int start(const char *dir, const char *object) {
    // Older kernels charge BPF memory against RLIMIT_MEMLOCK.
    struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &limit);
    struct bpf_object *obj = bpf_object__open_file(object, NULL);
    int err = libbpf_get_error(obj);
    if (err) return err;
    err = bpf_object__load(obj);
    if (!err) err = bpf_object__pin_maps(obj, dir);
    for (int i = 0; !err && i < 2; i++) {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, programs[i]);
        int map_fd = bpf_object__find_map_fd_by_name(obj, maps[i]);
        if (!prog || map_fd < 0) {
            err = -ENOENT;
            break;
        }
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dir, programs[i]) >=
            (int)sizeof(path)) {
            err = -ENAMETOOLONG;
            break;
        }
        err = bpf_program__pin(prog, path);
        if (err) break;
        if (bpf_prog_attach(bpf_program__fd(prog), map_fd, BPF_SK_MSG_VERDICT,
                            0))
            err = -errno;
    }
    bpf_object__close(obj);
    return err;
}

static int stats(void) {
    struct counters {
        unsigned long long bytes, drops;
    };
    struct counters total[2] = {0};
    int fd = bpf_obj_get("counts");
    if (fd < 0) return -errno;
    int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return -EINVAL;
    struct counters *cpu = calloc(cpus, sizeof(*cpu));
    if (!cpu) return -ENOMEM;
    int err = 0;
    for (__u32 side = 0; side < 2; side++) {
        if (bpf_map_lookup_elem(fd, &side, cpu)) {
            err = -errno;
            break;
        }
        for (int i = 0; i < cpus; i++) {
            total[side].bytes += cpu[i].bytes;
            total[side].drops += cpu[i].drops;
        }
    }
    free(cpu);
    close(fd);
    if (!err)
        printf(
            "{\"client\":{\"bytes\":%llu,\"drops\":%llu},"
            "\"server\":{\"bytes\":%llu,\"drops\":%llu}}\n",
            total[0].bytes, total[0].drops, total[1].bytes, total[1].drops);
    return err;
}

// Pin the programs before attaching so stop also works after partial setup.
// Older kernels can detach SK_MSG verdicts but cannot query the attachment.
static int remove_pin(const char *name) {
    return unlink(name) && errno != ENOENT ? -errno : 0;
}

static int detach(int side) {
    int prog_fd = bpf_obj_get(programs[side]);
    if (prog_fd < 0 && errno != ENOENT) return -errno;
    if (prog_fd >= 0) {
        int map_fd = bpf_obj_get(maps[side]);
        if (map_fd < 0 && errno != ENOENT) {
            close(prog_fd);
            return -errno;
        }
        int err = 0;
        if (map_fd >= 0) {
            if (bpf_prog_detach2(prog_fd, map_fd, BPF_SK_MSG_VERDICT) &&
                errno != ENOENT)
                err = -errno;
            close(map_fd);
        }
        close(prog_fd);
        if (err) return err;
    }
    int err = remove_pin(programs[side]);
    return err ? err : remove_pin(maps[side]);
}

int main(int argc, char **argv) {
    int err;
    if (argc == 4 && !strcmp(argv[1], "start")) {
        err = start(argv[2], argv[3]);
    } else if (argc == 3 &&
               (!strcmp(argv[1], "stats") || !strcmp(argv[1], "stop"))) {
        if (chdir(argv[2])) {
            err = -errno;
        } else if (!strcmp(argv[1], "stats")) {
            err = stats();
        } else {
            err = detach(0);
            int second = detach(1);
            if (!err) err = second;
            if (unlink("counts") && errno != ENOENT && !err) err = -errno;
        }
    } else {
        fprintf(
            stderr,
            "usage: sockmap_ctl start PIN_DIR OBJECT | {stats|stop} PIN_DIR\n");
        return 2;
    }
    if (err)
        fprintf(stderr, "sockmap_ctl %s (%s): %s\n", argv[1], argv[2],
                strerror(-err));
    return err ? 1 : 0;
}
