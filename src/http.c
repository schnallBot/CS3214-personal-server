/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))



// username and password -- bad to store in code but for now whatever
static const char* MY_USERNAME = "user0";
static const char* MY_PASSWORD = "thepassword";
static const char* MY_JWT_CODE = "secret sauce";  // for encoding JWT



/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        printf("Header: %s: %s\n", field_name, field_value);

        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Cookie")) {
            char* endptr2;
            strtok_r(field_value, "=", &endptr2);
            char* clientCookie = endptr2;
            ta->req_cookie = clientCookie;
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    buffer_appends(res, "HTTP/1.0 ");

    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found.", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    return "text/plain";
}

/** Helper that both parses and checks the string for invalid mutations. */
/*static int path_parse(char* string, size_t size, const char* source1, const char)
{
    for (int i = 0; i < size)
    {

    }
}*/


/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    char fname[PATH_MAX];

    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.

    // if the base directory is null, just use the request path.
    if (basedir == NULL)
    {
        snprintf(fname, sizeof fname, "%s", req_path);
    }
    else
    {
        snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
    }
    // If a bad sequence was found
    if (strstr(req_path, ".."))
    {
        // printf("ERROR: User attempted to use special path character sequences."); // Error reporting for server.
        // return send_not_found(ta); // Send not found.
        return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied -- attempting to access parent files.");
    }

    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    
    int filefd = open(fname, O_RDONLY); // File reading seems to be bugged here... why?
    if (filefd == -1) {
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from = 0, to = st.st_size - 1;

    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);

    bool success = send_response_header(ta);
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;

out:
    close(filefd);
    return success;
}

/* Handle calls to GET/POST api/login. */
static bool
handle_api(struct http_transaction *ta)
{
    // case 1: post request
    if (ta->req_method == HTTP_POST) {
        // check that body is not empty
        if (ta->req_content_len == 0)
            return send_error(ta, HTTP_BAD_REQUEST, "Invalid JSON object!");

        // try to parse request body for json
        char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
        json_t* userCredentials = json_loadb(body, ta->req_content_len, JSON_DECODE_ANY, NULL);
        if (userCredentials == NULL)
            return send_error(ta, HTTP_BAD_REQUEST, "Invalid JSON object!");

        // get username and password
        json_t* userJSON = json_object_get(userCredentials, "username");
        json_t* passJSON = json_object_get(userCredentials, "password");
        if (userJSON == NULL || passJSON == NULL)
            return send_error(ta, HTTP_BAD_REQUEST, "Invalid JSON object!");

        const char* userSTR = json_string_value(userJSON);
        const char* passSTR = json_string_value(passJSON);
        if (userSTR == NULL || passSTR == NULL)
            return send_error(ta, HTTP_BAD_REQUEST, "Invalid JSON object!");

        // if username or password doesn't match, 403 error
        if (strcmp(userSTR, MY_USERNAME) || strcmp(passSTR, MY_PASSWORD))
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        
        // correct! --> create a JWT for the user
        jwt_t* myToken;
        jwt_new(&myToken);
        jwt_add_grant(myToken, "sub", "user0");
        time_t now = time(NULL);
        jwt_add_grant_int(myToken, "iat", now);
        jwt_add_grant_int(myToken, "exp", now + 3600 * 24);
        jwt_set_alg(myToken, JWT_ALG_HS256, (unsigned char*)MY_JWT_CODE, strlen(MY_JWT_CODE));
        char* grants = jwt_get_grants_json(myToken, NULL);  // what to return to client in body
        char* encoded = jwt_encode_str(myToken);  // cookies to give to client

        // response header stuff
        ta->resp_status = HTTP_OK;
        http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/", encoded);  // this is the cookie
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");

        // add JWT to response body
        buffer_appends(&ta->resp_body, grants);

        // finally... send response! (headers + body)
        bool success = send_response(ta);

        free(grants);
        free(encoded);
        return success;
    }

    // case 2: get request
    else if (ta->req_method == HTTP_GET) {
        // status + response header should always be same for this one
        ta->resp_status = HTTP_OK;
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");

        // check for existence of cookies
        if (ta->req_cookie == NULL) {
            buffer_appends(&ta->resp_body, "{}");
            return send_response(ta);
        }

        // get client cookie and validate it
        char* clientCookie = ta->req_cookie;
        jwt_t* clientCookieDecoded;
        if (jwt_decode(&clientCookieDecoded, clientCookie, (unsigned char*)MY_JWT_CODE, strlen(MY_JWT_CODE))) {
            buffer_appends(&ta->resp_body, "{}");
            return send_response(ta);
        }

        // valid cookie! --> return client claims
        char* grants = jwt_get_grants_json(clientCookieDecoded, NULL);
        buffer_appends(&ta->resp_body, grants);
        bool success = send_response(ta);

        free(grants);
        return success;
    }

    // case 3: neither (invalid)
    else {
        return send_error(ta, HTTP_METHOD_NOT_ALLOWED, "Method not allowed.");
    }
}

/* Handle calls to GET private/... */
static bool
handle_private(struct http_transaction *ta, char *basedir)
{
    // check for existence of cookies
    if (ta->req_cookie == NULL)
        return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");

    // get client cookie and validate it
    char* clientCookie = ta->req_cookie;
    jwt_t* clientCookieDecoded;
    if (jwt_decode(&clientCookieDecoded, clientCookie, (unsigned char*)MY_JWT_CODE, strlen(MY_JWT_CODE)))
        return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");

    // valid cookie! --> give client the file (only works for static assets for now)
    return handle_static_asset(ta, basedir);
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;
    ta.req_cookie = NULL;  // no cookies by default

    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;

    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server"); // Custom server name
    buffer_init(&ta.resp_body, 0);

    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta);
    } else
    if (STARTS_WITH(req_path, "/private")) {
        rc = handle_private(&ta, server_root);
    } else {
        rc = handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return rc;
}
