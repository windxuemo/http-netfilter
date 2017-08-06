#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>

#define MIN_HTTP_REQ_LEN 16
#define HTTP_METHODS_AMOUNT 8

static struct nf_hook_ops nfho;
static char *http_methods[HTTP_METHODS_AMOUNT] = {"GET", "OPTIONS", "HEAD", "POST",
                                                  "PUT", "DELETE", "TRACE", "CONNECT"};

int check_valid_method(const unsigned char *tcp_data);

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
        unsigned char *it;
        int data_length;

        tcp_header = tcp_hdr(skb);

        // we get to the packet data portion by multiplying the data offset by 4
        // so if doff is 5 then we need to move 20 bytes from the beginning of the tcp header
        // which is also why we convert tcp_header to an unsigned char pointer (byte sized)
        tcp_data = (unsigned char *)((unsigned char*)tcp_header + (tcp_header->doff * 4));
        tail = skb_tail_pointer(skb); // points to the end of the data

        data_length = tail - tcp_data;

        if(data_length < MIN_HTTP_REQ_LEN) // minimum length of a HTTP request packet
                return NF_ACCEPT;

        int res;

        res = check_valid_method(tcp_data);

        if (res ==  -1)
                return NF_ACCEPT;

        int end_of_method_ind = strlen(http_methods[res]);

        if (tcp_data[end_of_method_ind] != ' ') // missing sp after method
                return NF_ACCEPT;

        return NF_DROP;
}

int check_valid_method(const unsigned char *tcp_data)
{
        int i;
        char *method_pos; // the address of the method string that is a part of tcp_data
        for (i = 0; i < HTTP_METHODS_AMOUNT; i++) {
                method_pos = strnstr(tcp_data, http_methods[i], strlen(http_methods[i]));
                if (method_pos != NULL) {
                        if(method_pos == tcp_data) // means that the method was found in index 0 (same address)
                                return i;
                }
        }
        return -1;
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

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
        nf_unregister_hook(&nfho);                     //cleanup – unregister hook
}
