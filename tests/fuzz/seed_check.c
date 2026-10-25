/*
 * seed_check.c - smoke-test the libFuzzer seed corpus.
 *
 * libFuzzer's runtime is not available on every host (e.g. macOS CI runners),
 * so this plain-C harness reads each seed file and drives pkt_parse() directly.
 * It catches hard crashes (segfaults) and confirms the seeds parse the way the
 * generator intends. The real mutation fuzzing runs under libFuzzer+ASan in CI
 * (see `make fuzz` and .github/workflows/ci.yml).
 *
 * Usage: seed_check <corpus-dir>   (corpus-dir contains *.eth seed files)
 */
#include "packet.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void read_file(const char *path, unsigned char **out, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        fprintf(stderr, "open failed: %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0)
    {
        *out = NULL;
        *len = 0;
        fclose(f);
        return;
    }
    unsigned char *buf = malloc((size_t)n);
    if (!buf)
    {
        fprintf(stderr, "oom\n");
        exit(2);
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n)
    {
        fprintf(stderr, "short read: %s\n", path);
        exit(2);
    }
    fclose(f);
    *out = buf;
    *len = (size_t)n;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]);
        return 2;
    }
    DIR *d = opendir(argv[1]);
    if (!d)
    {
        fprintf(stderr, "opendir %s failed\n", argv[1]);
        return 2;
    }

    int parsed = 0, rejected = 0, files = 0;
    struct dirent *e;
    while ((e = readdir(d)))
    {
        const char *name = e->d_name;
        if (strlen(name) < 4 || strcmp(name + strlen(name) - 4, ".eth") != 0)
            continue;

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", argv[1], name);

        unsigned char *data;
        size_t len;
        read_file(path, &data, &len);
        files++;

        /* First byte is the link-layer selector; the rest is the frame. */
        unsigned int link =
            (len > 0 && data[0] == 0) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        const unsigned char *frame = (len > 0) ? data + 1 : data;
        size_t framelen = (len > 0) ? len - 1 : 0;

        pkt_info_t info;
        int rc = pkt_parse(frame, framelen, link, &info);

        printf("%-28s link=%-4d rc=%d", name, (int)link, rc);
        if (rc)
        {
            char s[64];
            inet_ntop(info.family == AF_INET6 ? AF_INET6 : AF_INET, &info.addr,
                      s, sizeof(s));
            printf("  %s %s/%s", s, info.proto == PROTO_UDP ? "udp" : "tcp",
                   info.family == AF_INET6 ? "(v6)" : "(v4)");
            parsed++;
        }
        else
        {
            printf("  (rejected)");
            rejected++;
        }
        printf("\n");

        free(data);
    }
    closedir(d);

    printf("\n%d file(s): %d parsed, %d rejected\n", files, parsed, rejected);
    return files == 0 ? 2 : 0;
}
