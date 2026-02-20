#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define MAX_THREADS 250
#define CONNECT_TIMEOUT 1
#define MAX_TARGETS 50
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_RESET "\x1b[0m"
#define COLOR_BOLD "\x1b[1m"

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    int is_open;
    char service[50];
} port_result;

typedef struct {
    char target[100];
    int start_port;
    int end_port;
    int thread_count;
    int timeout;
    int show_closed;
    int resolve_services;
    int output_format;
    char output_file[256];
} scan_config;

typedef struct {
    scan_config config;
    int thread_id;
    int ports_assigned;
    port_result *results;
    int *result_count;
    pthread_mutex_t *mutex;
} thread_data;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    char hostname[256];
    int ports[65536];
    int port_count;
} scan_result;

const char* get_service_name(int port) {
    struct servent *service = getservbyport(htons(port), "tcp");
    if (service != NULL) {
        return service->s_name;
    }
    
    switch(port) {
        case 20: return "ftp-data";
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 80: return "http";
        case 110: return "pop3";
        case 111: return "rpcbind";
        case 135: return "msrpc";
        case 139: return "netbios-ssn";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "microsoft-ds";
        case 465: return "smtps";
        case 514: return "syslog";
        case 587: return "submission";
        case 631: return "ipp";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "ms-sql-s";
        case 1521: return "oracle";
        case 1701: return "l2tp";
        case 1723: return "pptp";
        case 3306: return "mysql";
        case 3389: return "ms-wbt-server";
        case 5432: return "postgresql";
        case 5900: return "vnc";
        case 5901: return "vnc-1";
        case 6000: return "x11";
        case 6379: return "redis";
        case 6667: return "irc";
        case 8000: return "http-alt";
        case 8008: return "http-alt";
        case 8080: return "http-proxy";
        case 8443: return "https-alt";
        case 8888: return "sun-answerbook";
        case 9090: return "websm";
        case 27017: return "mongod";
        case 27018: return "mongod";
        case 50000: return "db2";
        default: return "unknown";
    }
}

int validate_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

int resolve_hostname(const char *hostname, char *ip) {
    struct addrinfo hints, *res, *p;
    int status;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        return 0;
    }
    
    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        inet_ntop(p->ai_family, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
        break;
    }
    
    freeaddrinfo(res);
    return 1;
}

int check_port(const char *ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    int result = connect(sock, (struct sockaddr *)&server, sizeof(server));
    
    if (result < 0 && errno != EINPROGRESS) {
        close(sock);
        return 0;
    }
    
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof so_error;
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            close(sock);
            return 1;
        }
    }
    
    close(sock);
    return 0;
}

void* scan_worker(void *arg) {
    thread_data *data = (thread_data*)arg;
    int ports_per_thread = (data->config.end_port - data->config.start_port + 1) / data->config.thread_count;
    int start = data->config.start_port + (data->thread_id * ports_per_thread);
    int end = (data->thread_id == data->config.thread_count - 1) ? 
               data->config.end_port : start + ports_per_thread - 1;
    
    for (int port = start; port <= end; port++) {
        int is_open = check_port(data->config.target, port, data->config.timeout);
        
        if (is_open || data->config.show_closed) {
            pthread_mutex_lock(data->mutex);
            
            strcpy(data->results[*data->result_count].ip, data->config.target);
            data->results[*data->result_count].port = port;
            data->results[*data->result_count].is_open = is_open;
            
            if (data->config.resolve_services) {
                strcpy(data->results[*data->result_count].service, get_service_name(port));
            } else {
                strcpy(data->results[*data->result_count].service, "");
            }
            
            (*data->result_count)++;
            pthread_mutex_unlock(data->mutex);
        }
        
        if ((port - data->config.start_port) % 100 == 0) {
            printf("\r%s[%s+%s] %sThread %d%s: Scanning... %d/%d", 
                   COLOR_CYAN, COLOR_GREEN, COLOR_CYAN, COLOR_YELLOW, 
                   data->thread_id, COLOR_RESET, port - data->config.start_port + 1, 
                   data->config.end_port - data->config.start_port + 1);
            fflush(stdout);
        }
    }
    
    return NULL;
}

void display_banner() {
    printf("%s", COLOR_CYAN);
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         ADVANCE Port Scanner - Latest Edition     ║\n");
    printf("║                    Version 2.0.1                        ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("%s", COLOR_RESET);
}

void display_help() {
    printf("\n%s[+] Usage:%s\n", COLOR_GREEN, COLOR_RESET);
    printf("  Basic scan: ./scanner <target>\n");
    printf("  Range scan: ./scanner <target> <start_port> <end_port>\n");
    printf("  Full scan : ./scanner <target> -p-\n\n");
    
    printf("%s[+] Options:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  -p <ports>      Port range (e.g., 1-1000, 80,443,8080)\n");
    printf("  -t <threads>    Number of threads (default: 100, max: 500)\n");
    printf("  -T <timeout>    Timeout in seconds (default: 2)\n");
    printf("  -o <file>       Output to file\n");
    printf("  -s              Resolve service names\n");
    printf("  -v              Verbose output (show closed ports)\n");
    printf("  -h              Display this help\n\n");
    
    printf("%s[+] Examples:%s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("  ./scanner google.com\n");
    printf("  ./scanner 192.168.1.1 1 1024\n");
    printf("  ./scanner 10.0.0.1 -p 22,80,443 -t 50 -s -o results.txt\n");
}

void parse_port_range(const char *port_str, int *start, int *end) {
    if (strcmp(port_str, "-") == 0 || strcmp(port_str, "-p-") == 0) {
        *start = 1;
        *end = 65535;
        return;
    }
    
    char *dash = strchr(port_str, '-');
    if (dash) {
        *start = atoi(port_str);
        *end = atoi(dash + 1);
    } else {
        *start = *end = atoi(port_str);
    }
}

void save_results(port_result *results, int count, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("%s[-] Error: Cannot create output file%s\n", COLOR_RED, COLOR_RESET);
        return;
    }
    
    time_t now = time(NULL);
    fprintf(fp, "# Port Scan Results - %s", ctime(&now));
    fprintf(fp, "# %s\n\n", "============================================================");
    
    for (int i = 0; i < count; i++) {
        if (results[i].is_open) {
            fprintf(fp, "%-8d %-15s %s\n", 
                    results[i].port, 
                    results[i].service, 
                    results[i].ip);
        }
    }
    
    fclose(fp);
    printf("%s[+] Results saved to: %s%s\n", COLOR_GREEN, filename, COLOR_RESET);
}

int main(int argc, char *argv[]) {
    display_banner();
    
    scan_config config;
    memset(&config, 0, sizeof(config));
    
    config.thread_count = 100;
    config.timeout = 2;
    config.start_port = 1;
    config.end_port = 1024;
    config.show_closed = 0;
    config.resolve_services = 1;
    
    if (argc < 2) {
        display_help();
        printf("\n%s[?] Enter target IP or hostname: %s", COLOR_BLUE, COLOR_RESET);
        fgets(config.target, sizeof(config.target), stdin);
        config.target[strcspn(config.target, "\n")] = 0;
        
        if (strlen(config.target) == 0) {
            printf("%s[-] No target specified. Exiting.%s\n", COLOR_RED, COLOR_RESET);
            return 1;
        }
        
        printf("%s[?] Enter port range [1-1024]: %s", COLOR_BLUE, COLOR_RESET);
        char port_input[100];
        fgets(port_input, sizeof(port_input), stdin);
        port_input[strcspn(port_input, "\n")] = 0;
        
        if (strlen(port_input) > 0) {
            parse_port_range(port_input, &config.start_port, &config.end_port);
        }
        
        printf("%s[?] Use default settings? (y/n): %s", COLOR_BLUE, COLOR_RESET);
        char choice = getchar();
        if (choice != 'y' && choice != 'Y') {
            printf("%s[?] Threads [100]: %s", COLOR_BLUE, COLOR_RESET);
            char thread_input[10];
            scanf("%s", thread_input);
            if (atoi(thread_input) > 0) config.thread_count = atoi(thread_input);
            
            printf("%s[?] Timeout [2]: %s", COLOR_BLUE, COLOR_RESET);
            char timeout_input[10];
            scanf("%s", timeout_input);
            if (atoi(timeout_input) > 0) config.timeout = atoi(timeout_input);
        }
    } else {
        strcpy(config.target, argv[1]);
        
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
                parse_port_range(argv[i + 1], &config.start_port, &config.end_port);
                i++;
            } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
                config.thread_count = atoi(argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
                config.timeout = atoi(argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                strcpy(config.output_file, argv[i + 1]);
                i++;
            } else if (strcmp(argv[i], "-s") == 0) {
                config.resolve_services = 1;
            } else if (strcmp(argv[i], "-v") == 0) {
                config.show_closed = 1;
            } else if (strcmp(argv[i], "-h") == 0) {
                display_help();
                return 0;
            } else if (i == 2 && argc == 4) {
                config.start_port = atoi(argv[2]);
                config.end_port = atoi(argv[3]);
            }
        }
    }
    
    if (config.thread_count > MAX_THREADS) {
        config.thread_count = MAX_THREADS;
        printf("%s[!] Thread count limited to %d%s\n", COLOR_YELLOW, MAX_THREADS, COLOR_RESET);
    }
    
    char ip_address[INET_ADDRSTRLEN];
    
    if (!validate_ip(config.target)) {
        printf("%s[*] Resolving hostname: %s%s\n", COLOR_YELLOW, config.target, COLOR_RESET);
        if (!resolve_hostname(config.target, ip_address)) {
            printf("%s[-] Failed to resolve hostname%s\n", COLOR_RED, COLOR_RESET);
            return 1;
        }
        printf("%s[+] Host resolved: %s -> %s%s\n", COLOR_GREEN, config.target, ip_address, COLOR_RESET);
    } else {
        strcpy(ip_address, config.target);
    }
    
    printf("\n%s[+] Configuration:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s•%s Target     : %s\n", COLOR_GREEN, COLOR_RESET, config.target);
    printf("  %s•%s IP Address : %s\n", COLOR_GREEN, COLOR_RESET, ip_address);
    printf("  %s•%s Port Range : %d - %d (%d ports)\n", COLOR_GREEN, COLOR_RESET, 
           config.start_port, config.end_port, config.end_port - config.start_port + 1);
    printf("  %s•%s Threads    : %d\n", COLOR_GREEN, COLOR_RESET, config.thread_count);
    printf("  %s•%s Timeout    : %ds\n", COLOR_GREEN, COLOR_RESET, config.timeout);
    printf("  %s•%s Services   : %s\n", COLOR_GREEN, COLOR_RESET, 
           config.resolve_services ? "Yes" : "No");
    
    printf("\n%s[+] Starting scan...%s\n\n", COLOR_BOLD, COLOR_RESET);
    
    time_t scan_start = time(NULL);
    
    port_result *results = malloc(sizeof(port_result) * 65536);
    int result_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_t threads[MAX_THREADS];
    thread_data thread_args[MAX_THREADS];
    
    strcpy(config.target, ip_address);
    
    for (int i = 0; i < config.thread_count; i++) {
        thread_args[i].config = config;
        thread_args[i].thread_id = i;
        thread_args[i].results = results;
        thread_args[i].result_count = &result_count;
        thread_args[i].mutex = &mutex;
        
        pthread_create(&threads[i], NULL, scan_worker, &thread_args[i]);
    }
    
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    time_t scan_end = time(NULL);
    double scan_duration = difftime(scan_end, scan_start);
    
    printf("\n\n%s╔════════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║            Scan Complete                   ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╚════════════════════════════════════════════╝%s\n", COLOR_CYAN, COLOR_RESET);
    
    printf("\n%s[+] Open Ports Found:%s\n", COLOR_GREEN, COLOR_RESET);
    printf("  %sPORT     SERVICE%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  %s------    -------%s\n", COLOR_BOLD, COLOR_RESET);
    
    int open_count = 0;
    for (int i = 0; i < result_count; i++) {
        if (results[i].is_open) {
            printf("  %s%-8d%s  %s%-15s%s\n", 
                   COLOR_RED, results[i].port, COLOR_RESET,
                   COLOR_YELLOW, results[i].service, COLOR_RESET);
            open_count++;
        } else if (config.show_closed) {
            printf("  %s%-8d%s  %s%-15s%s %s[closed]%s\n", 
                   COLOR_BLUE, results[i].port, COLOR_RESET,
                   COLOR_BLUE, results[i].service, COLOR_RESET,
                   COLOR_RED, COLOR_RESET);
        }
    }
    
    printf("\n%s[+] Statistics:%s\n", COLOR_CYAN, COLOR_RESET);
    printf("  %s•%s Total ports scanned : %d\n", COLOR_GREEN, COLOR_RESET, 
           config.end_port - config.start_port + 1);
    printf("  %s•%s Open ports found    : %d\n", COLOR_GREEN, COLOR_RESET, open_count);
    printf("  %s•%s Time taken          : %.2f seconds\n", COLOR_GREEN, COLOR_RESET, scan_duration);
    printf("  %s•%s Scan speed          : %.0f ports/second\n", COLOR_GREEN, COLOR_RESET, 
           (config.end_port - config.start_port + 1) / scan_duration);
    
    if (strlen(config.output_file) > 0) {
        save_results(results, result_count, config.output_file);
    }
    
    free(results);
    pthread_mutex_destroy(&mutex);
    
    printf("\n%s[+] Scan completed successfully!%s\n", COLOR_GREEN, COLOR_RESET);
    
    return 0;
}