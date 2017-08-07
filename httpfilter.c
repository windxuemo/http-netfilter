#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>

#define MIN_HTTP_REQ_LEN 16

static struct nf_hook_ops nfho;
static char *http_methods[] = {"GET", "OPTIONS", "HEAD", "POST",
                              "PUT", "DELETE", "TRACE", "CONNECT", ""};
static char *http_versions[] = {"0.9", "1.0", "1.1", "1.2", "2.0", ""};
static int check_valid_option(const unsigned char *tcp_data, char *options[]);
static bool check_ws_upgrade(const unsigned char *tcp_data, int data_length);

/*
This function assumes a packet is HTTP if it abides exactly by the format specified for a request line in
a HTTP request in the RFC. There is no header checking (except for seeing if there's an ugprade header)
since it is not a must to have headers in a HTTP request.

There is no need for checking for HTTPS specifically because the handshake is not done via the HTTP protocol
like with websockets and once HTTP over SSL/TLS is actually used, everything is already encrypted.
*/
unsigned int http_filter_hook(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
        if (!skb) // empty network packet
                return NF_ACCEPT;

        struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); 
        struct tcphdr *tcp_header;
        if (ip_header->protocol != IPPROTO_TCP)
                return NF_ACCEPT;

        unsigned char *tcp_data;
        unsigned char *tail;
        int data_length;

        tcp_header = tcp_hdr(skb);

        // we get to the packet data portion by multiplying the data offset by 4
        // so if doff is 5 then we need to move 20 bytes from the beginning of the tcp header
        // which is also why we convert tcp_header to an unsigned char pointer (byte sized)
        tcp_data = (unsigned char *)((unsigned char*)tcp_header + (tcp_header->doff * 4));
        tail = skb_tail_pointer(skb); // points to the end of the data

        data_length = tail - tcp_data;

        // i wish i could use regexps here
        if(data_length < MIN_HTTP_REQ_LEN) // minimum length of a HTTP request packet
                return NF_ACCEPT;

        int res;

        res = check_valid_option(tcp_data, http_methods);

        if (res ==  -1)
                return NF_ACCEPT;

        int end_of_method_ind = strlen(http_methods[res]);

        if (tcp_data[end_of_method_ind] != ' ') // missing sp after method
                return NF_ACCEPT;

        if (tcp_data[end_of_method_ind + 1] != '/') // indicator that the URL is starting
                return NF_ACCEPT;

        int i;
        for(i = end_of_method_ind + 2; i < data_length; i++) {
                if (tcp_data[i] == '\0' || tcp_data[i] == '\n' || tcp_data[i] == '\r')
                        return NF_ACCEPT;
                if (tcp_data[i] == ' ') // managed to find a space in this line
                        break;
        }
        if (i == data_length) // we can't be sure the data is null terminated
                return NF_ACCEPT;

        char *version_pos;
        char *http_ver_beginning_p = tcp_data + i + 1; // start_of_packet + offset_to_2ndspace + 1
        version_pos = strnstr(http_ver_beginning_p, "HTTP/", 5);
        if (version_pos == NULL)
                return NF_ACCEPT;

        if (version_pos != http_ver_beginning_p) // one character after the space
                return NF_ACCEPT;

        res = check_valid_option(http_ver_beginning_p + 5, http_versions);
        if (res == -1)
                return NF_ACCEPT;

        char *end_of_version = http_ver_beginning_p + 5 + strlen(http_versions[res]);
        if (end_of_version[0] != '\r' || end_of_version[1] != '\n') // bad end of line
                return NF_ACCEPT;

        if (check_ws_upgrade(tcp_data, data_length))
                return NF_ACCEPT;

        return NF_DROP;
}

/*
Checks if the data given starts with a valid option from the options array given and returns the index in the
options array of the option that was found, else returns -1
*/
static int check_valid_option(const unsigned char *tcp_data, char *options[])
{
        int i = 0;
        char **it;
        char *option_pos;
        it = options;
        while (*it != "") {
                option_pos = strnstr(tcp_data, *it, strlen(*it));
                if (option_pos != NULL) {
                        if (option_pos == tcp_data) // means that the option was found in index 0 (same address)
                                return i;
                }
                it++;
                i++;
        }
        return -1;
}

/*
Called after determining the packet is a valid HTTP packet.
Checks if the packet is part of the websocket handshake.
*/
static bool check_ws_upgrade(const unsigned char *http_data, int data_length)
{
        char *res;
        res = strnstr(http_data, "\r\nUpgrade: websocket\r\n", data_length);
        if (res == NULL)
                return false;

        res = strnstr(http_data, "\r\nConnection: Upgrade\r\n", data_length);
        if (res == NULL)
                return false;

        return true;
}

int init_module()
{
        nfho.hook = (nf_hookfn *)http_filter_hook;
        nfho.hooknum = NF_INET_POST_ROUTING;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;

        int res = nf_register_hook(&nfho);
        if (res < 0) {
                printk(KERN_DEBUG "httpfilter: error registering hook in nf_register_hook()\n");
                return res;
        }

        return 0;
}

void cleanup_module()
{
        nf_unregister_hook(&nfho);
}
