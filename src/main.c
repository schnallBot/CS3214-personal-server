/*
 * Skeleton files for personal server assignment.
 *
 * @author Godmar Back
 * written for CS3214, Spring 2018.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "buffer.h"
#include "hexdump.h"
#include "http.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"
#include "threadpool.h"

#define N_THREADS 8  // for threadpool

/* Implement HTML5 fallback.
 * If HTML5 fallback is implemented and activated, the server should
 * treat requests to non-API paths specially.
 * If the requested file is not found, the server will serve /index.html
 * instead; that is, it should treat the request as if it
 * had been for /index.html instead.
 */
bool html5_fallback = false;

/** silent_mode. During benchmarking, this will be true */
bool silent_mode = false;

/** default token expiration time is 1 day */
int token_expiration_time = 24 * 60 * 60;

/** root from which static files are served */
char * server_root;

/*
 * A non-concurrent, iterative server that serves one client at a time.
 * For each client, it handles exactly 1 HTTP transaction.
 */
static void
server_loop(char *port_string, struct thread_pool* pool)
{
    int accepting_socket = socket_open_bind_listen(port_string, 10000);
    while (accepting_socket != -1) {
        fprintf(stderr, "Waiting for client...\n");
        int client_socket = socket_accept_client(accepting_socket);
        if (client_socket == -1)
            return;

        // set up new client
        struct http_client client;
        http_setup_client(&client, bufio_create(client_socket));

        // submit http transaction to threadpool
        struct future* f = thread_pool_submit(pool, http_handle_transaction, &client);
        future_get(f);
        future_free(f);

        bufio_close(client.bufio);
    }
}

static void
usage(char * av0)
{
    fprintf(stderr, "Usage: %s -p port [-R rootdir] [-h] [-e seconds]\n"
        "  -p port      port number to bind to\n"
        "  -R rootdir   root directory from which to serve files\n"
        "  -e seconds   expiration time for tokens in seconds\n"
        "  -h           display this help\n"
        , av0);
    exit(EXIT_FAILURE);
}

int
main(int ac, char *av[])
{
    int opt;
    char *port_string = NULL;
    while ((opt = getopt(ac, av, "ahp:R:se:")) != -1) {
        switch (opt) {
            case 'a':
                html5_fallback = true;
                break;

            case 'p':
                port_string = optarg;
                break;

            case 'e':
                token_expiration_time = atoi(optarg);
                fprintf(stderr, "token expiration time is %d\n", token_expiration_time);
                break;

            case 's':
                silent_mode = true;
                break;

            case 'R':
                server_root = optarg;
                break;

            case 'h':
            default:    /* '?' */
                usage(av[0]);
        }
    }

    if (port_string == NULL)
        usage(av[0]);

    /* We ignore SIGPIPE to prevent the process from terminating when it tries
     * to send data to a connection that the client already closed.
     * This may happen, in particular, in bufio_sendfile.
     */ 
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "Using port %s\n", port_string);

    // create new threadpool for handling http transactions
    struct thread_pool* pool = thread_pool_new(N_THREADS);

    // server loop
    server_loop(port_string, pool);

    // shutdown threadpool and exit
    thread_pool_shutdown_and_destroy(pool);
    exit(EXIT_SUCCESS);
}

