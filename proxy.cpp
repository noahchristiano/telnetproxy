#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <unordered_map>

#define MAXLINE 256 // line length
#define MAXRESP 65535 // response size

using namespace std;

typedef struct proxy_t {
	int portno;
	char *conf_name;
	std::unordered_map<string, bool> blocked;
	int sockfd;
	struct sockaddr_in serv_addr;
} proxy;

typedef struct client_t {
	int portno, sockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
} client;

typedef struct http_request_t {
	char *type;
	char *hostname;
	char *url;
	char *http_v;
} http_request;

typedef struct tcp_connection_t {
	int sockfd, portno;
	struct sockaddr_in serv_addr;
	struct hostent *server;
} tcp_connection;

int parse_config(proxy *p);
void parse_args(char *args[2], proxy *p);
int init_server(proxy *p);
int accept_client(client *c, proxy *p);
int parse_request(http_request *h, client *c);
bool is_blocked(http_request *h, proxy *p);
int tcp_connect(http_request *r, tcp_connection *t);
int send_request(http_request *r, tcp_connection *t);
int read_response(char *response, tcp_connection *t);
int send_response(char *response, client *c);
int send_not_found(client *c);
int send_bad_request(client *c);
void handle_child(client *c, proxy *p, pid_t p_pid);

int main(int argc, char **argv) {
	proxy p;
	p.portno = 80;
	p.conf_name = argv[1];

	printf("PARSING %s\n", p.conf_name);
	if (parse_config(&p) < 0) {
		fprintf(stderr, "parse config failed");
		exit(1);
	}
   	
   	printf("INIT PROXY: %d\n", p.portno);
	if (init_server(&p) > 0) {
    	fprintf(stderr, "init server error\n");
    	exit(1);
    }

    while (true) {
    	client c;
    	c.portno = p.portno;
        if (accept_client(&c, &p) > 0) {
        	fprintf(stderr, "accept client error\n");
        }
        fprintf(stderr, "accepted client: %d\n", c.portno);

    	// fork off new connection, handle it in child process
    	pid_t p_pid = getpid();
        pid_t pid = fork();
        if (pid == 0) { // child
        	handle_child(&c, &p, p_pid);

			// Close the connection socket to the client
			close(c.sockfd);
			exit(0);
        }
        else { // parent
        	close(c.sockfd);
        }
    }

	return 0;
}

// hanle child process
void handle_child(client *c, proxy *p, pid_t p_pid) {
    // parse client request
    http_request h;
    if (parse_request(&h, c) < 0) {
    	fprintf(stderr, "parse error\n");
    }

	if (strcmp("GET", h.type) == 0) { // check if get request
		fprintf(stderr, "RECIEVED GET REQUEST\n");
	  	fprintf(stderr, "url: %s\n", h.url);
    	fprintf(stderr, "hostname: %s\n", h.hostname);
    	fprintf(stderr, "http_v: %s\n", h.http_v);
	}
	else if (strcmp("QUIT", h.type) == 0) {
		fprintf(stderr, "RECIEVED QUIT\n");
		close(c->sockfd);
		kill(p_pid, SIGKILL);
		exit(0);
	}
	else {
		send_bad_request(c);
		close(c->sockfd);
		exit(0);
	}

	if (is_blocked(&h, p)) {
		fprintf(stderr, "request blocked: %s\n", h.hostname);
		send_not_found(c);
		close(c->sockfd);
		exit(0);
	}

	// Make TCP connection to the "real" Web server
	tcp_connection t;
	t.portno = 80;
	if (tcp_connect(&h, &t) > 0) {
		fprintf(stderr, "connection error: %s\n", h.hostname);
		close(t.sockfd);
		close(c->sockfd);
		exit(1);
	}

	// Send over an HTTP request
	if (send_request(&h, &t) > 0) {
		fprintf(stderr, "send request error: %s\n", h.url);
		close(t.sockfd);
		close(c->sockfd);
		exit(1);
	}

	// Receive the server's response
	char *resp = (char *) malloc(sizeof(char) * MAXRESP); // max tcp size
	if (read_response(resp, &t)) {
		fprintf(stderr, "read response error: %s\n", h.url);
		close(t.sockfd);
		close(c->sockfd);
		exit(1);
	}

	// Close the TCP connection to the server
	close(t.sockfd);

	// Send the server's response back to the client
	if (send_response(resp, c)) {
		fprintf(stderr, "send response error: %d\n", c->portno);
		close(c->sockfd);
		exit(1);
	}

	fprintf(stderr, "response sent: %d\n", c->portno);
}

// parse the configuration file
int parse_config(proxy *p) {
    FILE *file = std::fopen(p->conf_name , "r");
	if(file == NULL) {
		fprintf(stderr, "%s\n", "error opening file");
		return -1;
	}
    
	char line[300];
    while (fgets(line, 300, file)) {
	    if (strlen(line) > 1) { // skip empty line
	    	char *args[2];
		    args[0] = std::strtok(line, " ");
		    args[1] = std::strtok(NULL, " ");
		    parse_args(args, p);
	    }
	}

	return 0;
}

// helper method for parse_config
void parse_args(char *args[2], proxy *p) {
	if (strcmp(args[0], "port") == 0) {
		p->portno = stoi(args[1]);
		fprintf(stderr, "port: %d\n", p->portno);
	}
	else if (strcmp(args[0], "block") == 0) {
		if (args[1][strlen(args[1])-1] == '\n') { // remove newline
			args[1][strlen(args[1])-1] = '\0';
		}
		string site = string(args[1]);
		p->blocked.insert(make_pair(site, true));
		fprintf(stderr, "blocked: %s\n", args[1]);
	}
}

// open ports for the proxy and listen for clients
int init_server(proxy *p) {
    if (p->portno < 2) {
        fprintf(stderr, "%s\n", "ERROR, no port provided");
        return 1;
    }

    p->sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (p->sockfd < 0) {
        fprintf(stderr, "%s\n", "ERROR opening socket");
        return 1;
    }

    // bzero((char *) &p->serv_addr, sizeof(p->serv_addr));
    p->serv_addr.sin_family = AF_INET;
    p->serv_addr.sin_addr.s_addr = INADDR_ANY;
    p->serv_addr.sin_port = htons(p->portno);

    int yes = 1;
	setsockopt(p->sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (bind(p->sockfd, (struct sockaddr *) &p->serv_addr, sizeof(p->serv_addr)) < 0) {
        fprintf(stderr, "%s\n", "ERROR on binding");
        return 1;
    }

    return 0;
}

// initilize connection with the client
int accept_client(client *c, proxy *p) {
    listen(p->sockfd, 5);
    c->clilen = sizeof(c->cli_addr);
    c->sockfd = accept(
        p->sockfd,
        (struct sockaddr *) &c->cli_addr, 
        &c->clilen
    );

    if (c->sockfd < 0) {
        return 1;
    }

    return 0;
}

// parse the http get requests
int parse_request(http_request *h, client *c) {
	int consec_nl = 0;
	while (consec_nl < 2) { // wait for 2 consecutive newlines
		char input[256];

		if (read(c->sockfd, input, 256) < 0) {
			return 1;
		}

		// break input into lines
		char *line;
		line = std::strtok(input, "\n");
		while (line != NULL) {
			int len = strlen(line);
			if (len > 1) { // remove \r
				len--;
			}
			char *tok = (char *) malloc(sizeof(char) * len);
			strncpy(tok, line, len);

			// count consecutive newlines
			if (strcmp(tok, "\r") == 0) {
				consec_nl++;
			}
			else {
				consec_nl = 0;
			}

			tok = std::strtok(tok, " ");
			if (strcmp("GET", tok) == 0) { // parse request header
				h->type = tok;
				tok = std::strtok(NULL, " ");
				h->url = tok;
				tok = std::strtok(NULL, " ");
				h->http_v = tok;
			}
			else if (strcmp("QUIT", tok) == 0) {
				h->type = tok;
			}
			else if (strcmp("Host:", tok) == 0) { // get hostname
				tok = std::strtok(NULL, " ");
				h->hostname = tok;
			}

			line = std::strtok(NULL, "\n");
		}
	}

	return 0;
}

// send tcp connect out to the host
int tcp_connect(http_request *h, tcp_connection *t) {
    t->sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (t->sockfd < 0) {
        fprintf(stderr, "ERROR opening socket\n");
        return 1;
    }

    t->server = gethostbyname(h->hostname);

    if (t->server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        return 1;
    }

    // bzero((char *) &t->serv_addr, sizeof(t->serv_addr));
    t->serv_addr.sin_family = AF_INET;
    bcopy((char *) t->server->h_addr, 
         (char *) &t->serv_addr.sin_addr.s_addr,
         t->server->h_length);
    t->serv_addr.sin_port = htons(t->portno);

    if (connect(t->sockfd,(struct sockaddr *) &t->serv_addr, sizeof(t->serv_addr)) < 0) {
        fprintf(stderr, "ERROR connecting\n");
        return 1;
    }

    return 0;
}

// send get request to the host
int send_request(http_request *h, tcp_connection *t) {
	char *r = (char *) malloc(sizeof(char) * 256); //request
	sprintf(r, "%s %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n", 
		h->type,
		h->url,
		h->http_v,
		h->hostname
	);

    if (write(t->sockfd, r, strlen(r)) < 0) {
		return 1;
	}

	return 0;
}

// read http response from the host
int read_response(char *response, tcp_connection *t) {
	if (read(t->sockfd, response, MAXRESP) < 0) {
		return 1;
	}
	return 0;
}

// send http response to the child
int send_response(char *response, client *c) {
	if (write(c->sockfd, response, strlen(response)) < 0) {
		return 1;
	}
	return 0;
}

// urls must end with a backlash
bool is_blocked(http_request *h, proxy *p) {
	// extract host (ie http://www.facebook.com/ -> www.facebook.com)
	char *find_host = (char *) malloc(sizeof(char) * 256);
	strcpy(find_host, h->url);
	find_host = strtok(find_host, "/");
	find_host = strtok(NULL, "/");

	string host_str(find_host);

    if(p->blocked.find(host_str) != p->blocked.end()) {
    	return true;
    }
    return false;
}

// send 403 response to child
int send_not_found(client *c) {
	char resp[26] = "HTTP/1.1 403 Forbidden";
	if (write(c->sockfd, &resp, strlen(resp)) < 0) {
		return 1;
	}
	return 0;
}

// send 400 response to child
int send_bad_request(client *c) {
	char resp[26] = "HTTP/1.1 400 Bad Request";
	if (write(c->sockfd, &resp, strlen(resp)) < 0) {
		return 1;
	}
	return 0;
}