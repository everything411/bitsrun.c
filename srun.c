// SPDX-License-Identifier: MIT
/*
 * srun.c by everything411
 * Supported Arch: x86_64, i386, arm, aarch64, mips, mipsel
 * ( x86_64-linux-gnu-gcc | i686-linux-gnu-gcc | arm-linux-gnueabi-gcc | aarch64-linux-gnu-gcc ) -O2 -nostdlib -static -fno-builtin -fno-stack-protector srun.c -o srun
 * ( mipsel-linux-gnu-gcc | mips-linux-gnu-gcc ) -O2 -march=24kc -msoft-float -fno-pic -mno-abicalls -nostdlib -static -fno-builtin -fno-stack-protector srun.c -o srun
 */

/* ==========================================
 * 1. Architecture & Syscalls
 * ========================================== */

int main(int argc, char **argv);

#define AF_INET 2
#define IPPROTO_IP 0

#if defined(__x86_64__)
#define ARCH_NAME "x86_64"
#define SYS_read 0
#define SYS_write 1
#define SYS_close 3
#define SYS_socket 41
#define SYS_connect 42
#define SYS_exit 60
#define SOCK_STREAM 1

long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

void __attribute__((naked)) _start()
{
    __asm__ volatile(
        "pop %rdi\n"        // argc -> rdi
        "mov %rsp, %rsi\n"  // argv -> rsi
        "andq $-16, %rsp\n" // align stack to 16 bytes
        "call main\n"
        "mov %rax, %rdi\n"
        "mov $60, %rax\n" // exit
        "syscall");
}

#elif defined(__i386__)
#define ARCH_NAME "i386"
#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_close 6
#define SYS_socket 359 /* Linux 4.3+ direct socket calls */
#define SYS_connect 362
#define SOCK_STREAM 1

long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile(
        "pushl %%ebx\n"
        "movl %2, %%ebx\n"
        "int $0x80\n"
        "popl %%ebx"
        : "=a"(ret) : "a"(n), "r"(a1), "c"(a2), "d"(a3) : "memory");
    return ret;
}

void __attribute__((naked)) _start()
{
    __asm__ volatile(
        "pop %eax\n"       // argc
        "mov %esp, %ecx\n" // argv
        "push %ecx\n"
        "push %eax\n"
        "call main\n"
        "mov %eax, %ebx\n"
        "mov $1, %eax\n" // exit
        "int $0x80");
}

#elif defined(__arm__)
#define ARCH_NAME "arm"
#define SYS_exit 1
#define SYS_read 3
#define SYS_write 4
#define SYS_close 6
#define SYS_socket 281
#define SYS_connect 283
#define SOCK_STREAM 1

long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ volatile(
        "mov r7, %1\n"
        "mov r0, %2\n"
        "mov r1, %3\n"
        "mov r2, %4\n"
        "swi 0x0\n"
        "mov %0, r0"
        : "=r"(ret) : "r"(n), "r"(a1), "r"(a2), "r"(a3)
        : "r0", "r1", "r2", "r7", "memory");
    return ret;
}

void __attribute__((naked)) _start()
{
    __asm__ volatile(
        "ldr r0, [sp]\n"   // argc
        "add r1, sp, #4\n" // argv
        "bl main\n"
        "mov r7, #1\n" // exit
        "swi 0x0");
}

int __aeabi_idiv(int numerator, int denominator)
{
    int sign = 0;

    if (denominator == 0)
        return 0;
    if ((numerator < 0) != (denominator < 0))
        sign = 1;

    unsigned int n = (numerator < 0) ? -(unsigned int)numerator : (unsigned int)numerator;
    unsigned int d = (denominator < 0) ? -(unsigned int)denominator : (unsigned int)denominator;
    unsigned int q = 0;

    if (d <= n)
    {
        int i;
        for (i = 31; i >= 0; i--)
        {
            if ((n >> i) >= d)
            {
                q += (1U << i);
                n -= (d << i);
            }
        }
    }

    return sign ? -(int)q : (int)q;
}

#elif defined(__aarch64__)
#define ARCH_NAME "aarch64"
#define SYS_close 57
#define SYS_read 63
#define SYS_write 64
#define SYS_exit 93
#define SYS_socket 198
#define SYS_connect 203
#define SOCK_STREAM 1

long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc 0" : "=r"(x0) : "r"(x8), "r"(x0), "r"(x1), "r"(x2) : "memory");
    return x0;
}

__asm__(
    ".section .text\n"
    ".global _start\n"
    ".type _start, %function\n"
    "_start:\n"
    "ldr x0, [sp]\n"
    "add x1, sp, #8\n"
    "bl main\n"
    "mov x8, #93\n"
    "svc #0\n");

#elif defined(__mips__)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ARCH_NAME "mipsel"
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define ARCH_NAME "mips"
#endif

#define SYS_BASE 4000
#define SYS_exit (SYS_BASE + 1)
#define SYS_read (SYS_BASE + 3)
#define SYS_write (SYS_BASE + 4)
#define SYS_close (SYS_BASE + 6)
#define SYS_socket (SYS_BASE + 183)
#define SYS_connect (SYS_BASE + 170)
#define SOCK_STREAM 2

long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a1;
    register long a1_reg __asm__("$5") = a2;
    register long a2_reg __asm__("$6") = a3;
    __asm__ volatile(
        "syscall"
        : "=r"(v0) : "r"(v0), "r"(a0), "r"(a1_reg), "r"(a2_reg)
        : "$7", "memory");
    return v0;
}

__asm__(
    ".section .text\n"
    ".global __start\n"
    ".align 2\n"
    "__start:\n"
    ".set noreorder\n"
    "lw $a0, 0($sp)\n"
    "addiu $a1, $sp, 4\n"
    "addiu $sp, $sp, -32\n"
    "jal main\n"
    "nop\n"
    "move $a0, $v0\n"
    "li $v0, 4001\n"
    "syscall\n"
    ".set reorder\n");

#else
#error "Unsupported Architecture"
#endif

/* Type Definitions */
typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

/* Syscall Wrappers */
_Noreturn void sys_exit(int code)
{
    syscall3(SYS_exit, code, 0, 0);
    __builtin_unreachable();
}
ssize_t sys_write(int fd, const void *buf, size_t count) { return syscall3(SYS_write, fd, (long)buf, count); }
ssize_t sys_read(int fd, void *buf, size_t count) { return syscall3(SYS_read, fd, (long)buf, count); }
int sys_close(int fd) { return syscall3(SYS_close, fd, 0, 0); }
int sys_socket(int domain, int type, int protocol) { return syscall3(SYS_socket, domain, type, protocol); }
int sys_connect(int sockfd, const void *addr, int addrlen) { return syscall3(SYS_connect, sockfd, (long)addr, addrlen); }

#define STDOUT 1

/* ==========================================
 * 2. Mini Libc (String & Memory)
 * ========================================== */

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        p++;
    return p - s;
}
void *memset(void *s, int c, size_t n)
{
    unsigned char *p = s;
    while (n--)
        *p++ = (unsigned char)c;
    return s;
}
void *memcpy(void *dest, const void *src, size_t n)
{
    char *d = dest;
    const char *s = src;
    while (n--)
        *d++ = *s++;
    return dest;
}

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strcpy(char *dest, const char *src)
{
    char *d = dest;
    while ((*d++ = *src++))
        ;
    return dest;
}
char *strcat(char *dest, const char *src)
{
    char *d = dest;
    while (*d)
        d++;
    while ((*d++ = *src++))
        ;
    return dest;
}

char *strstr(const char *haystack, const char *needle)
{
    if (!*needle)
        return (char *)haystack;
    for (; *haystack; haystack++)
    {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n)
        {
            h++;
            n++;
        }
        if (!*n)
            return (char *)haystack;
    }
    return 0;
}

void print(const char *s) { sys_write(STDOUT, s, strlen(s)); }

/* ==========================================
 * 3. Crypto (SHA1, TEA/XEncode, Base64)
 * ========================================== */

/* --- SHA1 Implementation --- */
typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

#define ROL(v, b) (((v) << (b)) | ((v) >> (32 - (b))))
#define BLK(i) (block[i & 15] = ROL(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i & 15], 1))

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a, b, c, d, e, block[16];
    for (int i = 0; i < 16; i++)
        block[i] = (((uint32_t)buffer[4 * i]) << 24) | (((uint32_t)buffer[4 * i + 1]) << 16) |
                   (((uint32_t)buffer[4 * i + 2]) << 8) | ((uint32_t)buffer[4 * i + 3]);
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    for (int i = 0; i < 20; i++)
    {
        uint32_t t = ROL(a, 5) + ((b & c) | (~b & d)) + e + ((i < 16) ? block[i] : BLK(i)) + 0x5A827999;
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = t;
    }
    for (int i = 20; i < 40; i++)
    {
        uint32_t t = ROL(a, 5) + (b ^ c ^ d) + e + BLK(i) + 0x6ED9EBA1;
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = t;
    }
    for (int i = 40; i < 60; i++)
    {
        uint32_t t = ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + BLK(i) + 0x8F1BBCDC;
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = t;
    }
    for (int i = 60; i < 80; i++)
    {
        uint32_t t = ROL(a, 5) + (b ^ c ^ d) + e + BLK(i) + 0xCA62C1D6;
        e = d;
        d = c;
        c = ROL(b, 30);
        b = a;
        a = t;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1Init(SHA1_CTX *context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len)
{
    uint32_t i, j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
        context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
            SHA1Transform(context->state, &data[i]);
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(uint8_t digest[20], SHA1_CTX *context)
{
    uint32_t i;
    uint8_t finalcount[8];
    for (i = 0; i < 8; i++)
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    SHA1Update(context, (uint8_t *)"\200", 1);
    while ((context->count[0] & 504) != 448)
        SHA1Update(context, (uint8_t *)"\0", 1);
    SHA1Update(context, finalcount, 8);
    for (i = 0; i < 20; i++)
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}

/* --- TEA / XEncode --- */
void sencode(const char *msg, int len, uint32_t *out, int *out_len, int is_key)
{
    int n = len / 4;
    if (len % 4 > 0)
        n++;
    memset(out, 0, (n + 2) * 4);
    for (int i = 0; i < len; i++)
    {
        out[i / 4] |= (uint32_t)(unsigned char)msg[i] << ((i % 4) * 8);
    }
    if (is_key)
    {
        out[n] = len;
        *out_len = n + 1;
    }
    else
    {
        *out_len = n;
    }
}
void lencode(uint32_t *data, int len, char *out, int is_key)
{
    for (int i = 0; i < len; i++)
    {
        out[i * 4] = data[i] & 0xFF;
        out[i * 4 + 1] = (data[i] >> 8) & 0xFF;
        out[i * 4 + 2] = (data[i] >> 16) & 0xFF;
        out[i * 4 + 3] = (data[i] >> 24) & 0xFF;
    }
    out[len * 4] = 0;
}

void xencode(const char *msg, int msg_len, const char *key, int key_len, char *output_buf)
{
    if (msg_len == 0)
    {
        output_buf[0] = 0;
        return;
    }
    static uint32_t v[1024];
    static uint32_t k[256];
    int n = 0, k_len = 0;
    sencode(msg, msg_len, v, &n, 1);
    n--;
    sencode(key, key_len, k, &k_len, 0);
    if (k_len < 4)
        k_len = 4;
    uint32_t z = v[n], y = v[0], c = 0x9E3779B9, m, e, d = 0;
    int p, q = 6 + 52 / (n + 1);
    while (q > 0)
    {
        d += c;
        e = (d >> 2) & 3;
        for (p = 0; p < n; p++)
        {
            y = v[p + 1];
            m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (k[(p & 3) ^ e] ^ z);
            v[p] += m;
            z = v[p];
        }
        y = v[0];
        m = (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y)) + (k[(p & 3) ^ e] ^ z);
        v[n] += m;
        z = v[n];
        q--;
    }
    lencode(v, n + 1, output_buf, 0);
}

void fake_base64(const char *data, int len, char *out)
{
    const char *cust_table = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
    int i = 0, j = 0;
    uint32_t a, b, c, t;
    while (i < len)
    {
        a = i < len ? (unsigned char)data[i++] : 0;
        b = i < len ? (unsigned char)data[i++] : 0;
        c = i < len ? (unsigned char)data[i++] : 0;
        t = (a << 16) + (b << 8) + c;
        out[j++] = cust_table[(t >> 18) & 63];
        out[j++] = cust_table[(t >> 12) & 63];
        out[j++] = cust_table[(t >> 6) & 63];
        out[j++] = cust_table[t & 63];
    }
    int mod = len % 3;
    if (mod == 1)
    {
        out[j - 1] = '=';
        out[j - 2] = '=';
    }
    else if (mod == 2)
    {
        out[j - 1] = '=';
    }
    out[j] = 0;
}

void url_encode(const char *str, char *out)
{
    const char *hex = "0123456789ABCDEF";
    while (*str)
    {
        if ((*str >= 'a' && *str <= 'z') || (*str >= 'A' && *str <= 'Z') ||
            (*str >= '0' && *str <= '9') || *str == '-' || *str == '_' || *str == '.' || *str == '~')
        {
            *out++ = *str;
        }
        else
        {
            *out++ = '%';
            *out++ = hex[(*str >> 4) & 0xF];
            *out++ = hex[*str & 0xF];
        }
        str++;
    }
    *out = 0;
}

/* ==========================================
 * 4. Network & Utils
 * ========================================== */

struct sockaddr_in
{
    short sin_family;
    unsigned short sin_port;
    struct
    {
        unsigned int s_addr;
    } sin_addr;
    char sin_zero[8];
};

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define SRUN_IP 0x3700000A // 10.0.0.55
#define SRUN_PORT 0x5000   // 80
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define SRUN_IP 0x0A000037 // 10.0.0.55
#define SRUN_PORT 0x0050   // 80
#else
#error "unsupported byte order"
#endif

int connect_srun()
{
    int fd = sys_socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (fd < 0)
        return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = SRUN_PORT;
    addr.sin_addr.s_addr = SRUN_IP;
    if (sys_connect(fd, &addr, sizeof(addr)) < 0)
    {
        sys_close(fd);
        return -1;
    }
    return fd;
}

char recv_buf[4096];
void http_get(const char *path, char *output, int max_len)
{
    int fd = connect_srun();
    if (fd < 0)
    {
        print("Socket error\n");
        sys_exit(1);
    }
    static char req[512];
    strcpy(req, "GET ");
    strcat(req, path);
    strcat(req, " HTTP/1.0\r\nHost: 10.0.0.55\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 Srun client\r\n\r\n");

    sys_write(fd, req, strlen(req));
    int total = 0, r;
    while ((r = sys_read(fd, recv_buf, 4096)) > 0)
    {
        if (total + r < max_len)
        {
            memcpy(output + total, recv_buf, r);
            total += r;
        }
    }
    output[total] = 0;
    sys_close(fd);
}

// ugly but work
void get_json_value(const char *json, const char *key, char *out)
{
    // skip HTTP header
    json = strstr(json, "\r\n\r\n");
    if (!json)
    {
        out[0] = 0;
        return;
    }

    static char search[64];
    strcpy(search, "\"");
    strcat(search, key);
    strcat(search, "\"");
    char *p = strstr(json, search);
    if (!p)
    {
        out[0] = 0;
        return;
    }
    p += strlen(search);
    while (*p && *p != ':')
        p++;
    while (*p && (*p == ':' || *p == ' ' || *p == '"'))
        p++;
    int i = 0;
    while (*p && *p != '"')
        out[i++] = *p++;
    out[i] = 0;
}

/* ==========================================
 * 5. Main Logic
 * ========================================== */

void print_usage()
{
    print("srun client (" ARCH_NAME ")\n");
    print("Usage:\n  srun login <user> <pass>\n  srun logout\n  srun status\n");
    sys_exit(1);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        print_usage();
    char *action = argv[1];

    if (strcmp(action, "login") == 0)
    {
        if (argc < 4)
        {
            print("Usage: srun login <user> <pass>\n");
            return 1;
        }

        if (strlen(argv[2]) > 64 || strlen(argv[3]) > 64)
        {
            print("Error: Username or password too long.\n");
            return 1;
        }
    }
    else if (strcmp(action, "logout") != 0 && strcmp(action, "status") != 0)
    {
        print_usage();
    }

    /* Step 0: Check Status & Get IP */
    static char resp[4096];
    static char value[128];
    http_get("/cgi-bin/rad_user_info?callback=jsonp", resp, 4096);

    static char client_ip[64];
    get_json_value(resp, "error", value);

    // If "ok", we are online, use online_ip; otherwise use client_ip from detection
    if (strcmp(value, "ok") == 0)
    {
        get_json_value(resp, "online_ip", client_ip);
    }
    else
    {
        get_json_value(resp, "client_ip", client_ip);
    }

    /* --- Command: status --- */
    if (strcmp(action, "status") == 0)
    {
        if (strcmp(value, "ok") == 0)
        {
            static char user_name[128];
            get_json_value(resp, "user_name", user_name);
            print(client_ip);
            print(" ");
            print(user_name);
            print(" Online\n");
        }
        else
        {
            print(client_ip);
            print(" Offline\n");
        }
        return 0;
    }
    /* --- Command: logout --- */
    else if (strcmp(action, "logout") == 0)
    {
        print("Logging out...\n");
        http_get("/cgi-bin/srun_portal?callback=jsonp&action=logout", resp, 1024);
        get_json_value(resp, "error", value);
        print("Server says ");
        print(value);
        print("\n");
        return 0;
    }
    /* --- Command: login --- */
    else if (strcmp(action, "login") == 0)
    {
        if (strcmp(value, "ok") == 0)
        {
            print("Already online. IP: ");
            print(client_ip);
            get_json_value(resp, "user_name", value);
            print(" User: ");
            print(value);
            print("\n");
            return 0;
        }

        char *username = argv[2];
        char *password = argv[3];

        print("Detected IP: ");
        print(client_ip);
        print("\n");

        // 1. Get Challenge (64 bytes)
        static char path[512];
        strcpy(path, "/cgi-bin/get_challenge?callback=jsonp&username=");
        strcat(path, username);
        strcat(path, "&ip=");
        strcat(path, client_ip);

        http_get(path, resp, 4096);
        static char token[96];
        get_json_value(resp, "challenge", token);
        if (strlen(token) == 0)
        {
            print("Get token failed\n");
            return 1;
        }

        // 2. Encrypt Login Info (XEncode + Base64)
        static char json_data[512];
        strcpy(json_data, "{\"username\":\"");
        strcat(json_data, username);
        strcat(json_data, "\",\"password\":\""); // Real user password goes here
        strcat(json_data, password);
        strcat(json_data, "\",\"acid\":\"1\",\"ip\":\"");
        strcat(json_data, client_ip);
        strcat(json_data, "\",\"enc_ver\":\"srun_bx1\"}");

        static char xencoded[512];
        xencode(json_data, strlen(json_data), token, strlen(token), xencoded);

        // Pad length calculation for Base64
        int xlen = strlen(json_data);
        int n = xlen / 4;
        if (xlen % 4 > 0)
            n++;

        static char info[1024];
        strcpy(info, "{SRBX1}");
        fake_base64(xencoded, (n + 1) * 4, info + 7);

        // 3. Calculate Checksum (SHA1)
        static char chk_str[2048];
        strcpy(chk_str, token);
        strcat(chk_str, username);
        strcat(chk_str, token);
        // Should be hmac.md5(token, password), but server doesn't validate properly
        // Fake MD5 to skip HMAC implementation
        strcat(chk_str, "e10adc3949ba59abbe56e057f20f883e");
        strcat(chk_str, token);
        strcat(chk_str, "1");
        strcat(chk_str, token);
        strcat(chk_str, client_ip);
        strcat(chk_str, token);
        strcat(chk_str, "200");
        strcat(chk_str, token);
        strcat(chk_str, "1");
        strcat(chk_str, token);
        strcat(chk_str, info);

        SHA1_CTX sha1;
        uint8_t sha1_bin[20];
        SHA1Init(&sha1);
        SHA1Update(&sha1, (uint8_t *)chk_str, strlen(chk_str));
        SHA1Final(sha1_bin, &sha1);
        static char checksum[41];
        static char hex[] = "0123456789abcdef";
        for (int i = 0; i < 20; i++)
        {
            checksum[i * 2] = hex[sha1_bin[i] >> 4];
            checksum[i * 2 + 1] = hex[sha1_bin[i] & 0xF];
        }
        checksum[40] = 0;

        // 4. Send Login Request
        static char pwd_enc[] = "%7BMD5%7D"
                                "e10adc3949ba59abbe56e057f20f883e";
        static char info_enc[2048];
        url_encode(info, info_enc);

        strcpy(path, "/cgi-bin/srun_portal?callback=jsonp&action=login&username=");
        strcat(path, username);
        strcat(path, "&ac_id=1&ip=");
        strcat(path, client_ip);
        strcat(path, "&type=1&n=200&password=");
        strcat(path, pwd_enc);
        strcat(path, "&chksum=");
        strcat(path, checksum);
        strcat(path, "&info=");
        strcat(path, info_enc);

        print("Sending login...\n");
        http_get(path, resp, 4096);
        get_json_value(resp, "error", value);
        print("Server says ");
        print(value);
        print(" ");
        get_json_value(resp, "error_msg", value);
        print(value);
        print("\n");

        return 0;
    }

    else
    {
        print_usage();
    }

    return 0;
}
