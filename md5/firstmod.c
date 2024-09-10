#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/openat2.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include "md5.h"

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

MODULE_LICENSE("GPL v2");

static struct nf_hook_ops nfho, _nfho;
char md5_str[DATA_LEN + 1];     

void hex_str_to_bytes(const char *hex_str, unsigned char *bytes, size_t max_bytes) {  
    size_t hex_str_len = strlen(hex_str);  
    size_t num_bytes = hex_str_len / 2; // 每个十六进制对表示一个字节  
  
    // 确保不会超出目标数组的大小  
    if (num_bytes > max_bytes) {  
        num_bytes = max_bytes;  
    }  
  
    for (size_t i = 0; i < num_bytes; i++) {  
        // sscanf会读取两个十六进制字符，并将它们转换为对应的字节值  
        sscanf(hex_str + i * 2, "%2hhx", &bytes[i]);  
    }  
}

// This func uses skb_copy_expand() to alloc a new skb, then puts it on rx
static unsigned int add_opts_to_iph_in(void *priv,
                              struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct sk_buff *skb_new;
    unsigned char *new_data;
    int ip_hdr_len, new_ip_hdr_len;
    // unsigned char custom_option[] = {0x83, 0x04, 0xde, 0xad}; // Example custom option
    
    md5_hash(md5_str, (unsigned char *)skb->data, skb->len);
	// printk("[string - %s] md5 value:\n", skb->data);
	// printk("%s\n", md5_str);

    unsigned char custom_option[40];
    custom_option[0] = 0xCA;  
    custom_option[1] = 0x28;  
    hex_str_to_bytes(md5_str, custom_option + 2, sizeof(custom_option) - 2);  
    // for(int i = 0; i < 40; i++){
    //     printk("%02x ", custom_option[i]);
    // }

    // Check if the packet is an IP packet
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // Only affect ICMP packet
    if(iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    // Modify packet with no options
    if(iph->ihl > 5)
        return NF_ACCEPT;

    // Ensure the packet is IPv4
    if (iph->version != 4)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl * 4;
    // printk(KERN_INFO "ip head len: %d bytes\n", ip_hdr_len);
    new_ip_hdr_len = ip_hdr_len + sizeof(custom_option);
    // printk(KERN_INFO "new ip head len: %d bytes\n", new_ip_hdr_len);

    // Create a new skb with additional space for the custom option
    skb_new = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + sizeof(custom_option), GFP_ATOMIC);
    // printk(KERN_INFO "trying to alloc new skb\n");

    if (!skb_new)
        return NF_DROP;

    skb_put(skb_new, sizeof(custom_option)); // Expand the skb to accommodate the new IP options
    new_data = skb_network_header(skb_new);

    // Move existing IP payload to the right place
    memmove(new_data + new_ip_hdr_len, new_data + ip_hdr_len, skb_new->len - new_ip_hdr_len);

    // Copy the original IP header to the new location
    memcpy(new_data, iph, ip_hdr_len);

    // Insert the custom IP option
    memcpy(new_data + ip_hdr_len, custom_option, sizeof(custom_option));

    // Adjust IP header fields
    iph = (struct iphdr *)new_data;
    iph->ihl = new_ip_hdr_len / 4;
    iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(custom_option));

    // Recompute the IP header checksum
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    skb_new->ip_summed = CHECKSUM_UNNECESSARY;
    skb_new->csum = skb_checksum(skb_new, iph->ihl*4, skb_new->len - iph->ihl*4, 0);
    // printk(KERN_INFO "skb ip_summed: %d, new skb ip_summed: %d\n", skb->ip_summed, skb_new->ip_summed);
    // printk(KERN_INFO "skb csum: 0x%x, new skb csum: 0x%x\n", skb->csum, skb_new->csum);
    // printk(KERN_INFO "new checksum 0x%x\n", iph->check);

    // Update skb pointers
    // skb_new->network_header = (unsigned char *)iph - skb_new->data;
    skb_new->transport_header += sizeof(custom_option);


    // char* icmph;
    // icmph = (char*) skb_transport_header(skb_new);
    // unsigned char * iph_test;
    // iph_test = (unsigned char *) skb_network_header(skb_new);
    // int i = 0;
    // for( ; i < 30; i = i + 4){
    //     printk("%02x %02x %02x %02x ", *(iph_test + i), *(iph_test + i + 1), *(iph_test + i + 2), *(iph_test + i + 3));
    // }

    // Free the old skb and use the new one
    netif_rx(skb_new);
    // consume_skb(skb);
    // kfree_skb(skb);

    return NF_DROP;
}

// This func uses skb directly as the headroom is enough to store options
static unsigned int add_opts_to_iph_out(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state){
    struct iphdr *iph;
    struct ethhdr *ethh;
    unsigned char * mac_header, * ip_header;
    int ip_hdr_len, new_ip_hdr_len, mac_hdr_len;
    // unsigned char custom_option[40] = {0xca, 0x28, 0x0, 0x0};
    md5_hash(md5_str, (unsigned char *)skb->data, skb->len);
	// printk("[string - %s] md5 value:\n", skb->data);
	// printk("%s\n", md5_str);

    unsigned char custom_option[40];
    custom_option[0] = 0xCA;  
    custom_option[1] = 0x28;  
    hex_str_to_bytes(md5_str, custom_option + 2, sizeof(custom_option) - 2);  
    // for(int i = 0; i < 40; i++){
    //     printk("%02x ", custom_option[i]);
    // }


    // Check if the packet is an IP packet
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    ip_header = skb_network_header(skb);
    if (!iph)
        return NF_ACCEPT;

    // Ensure the packet is IPv4
    if (iph->version != 4)
        return NF_ACCEPT;

    // Only affect ICMP packet
    if(iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    ethh = skb_eth_hdr(skb);
    mac_header = skb_mac_header(skb);

    ip_hdr_len = iph->ihl * 4;
    new_ip_hdr_len = ip_hdr_len + sizeof(custom_option);
    mac_hdr_len = ip_header - mac_header;

    // Reserve headroom by skb_push directly
    // printk(KERN_INFO "mac header len: %d, calced by pointers: %d\n", skb_mac_header_len(skb), mac_hdr_len);
    // printk(KERN_INFO "skb.headroom: %d\n", skb_headroom(skb));
    // printk(KERN_INFO "skb data 0x%llx, skb head 0x%llx, skb ip header 0x%llx\n", skb->data, skb->head, skb_network_header(skb));
    skb_push(skb, sizeof(custom_option));
    // printk(KERN_INFO "skb.headroom after push: %d\n", skb_headroom(skb));
    // printk(KERN_INFO "skb data 0x%llx, skb head 0x%llx, skb ip header 0x%llx\n", skb->data, skb->head, skb_network_header(skb));

    memmove(mac_header - sizeof(custom_option), mac_header, mac_hdr_len + ip_hdr_len);
    // printk(KERN_INFO "mac_header 0x%p, new_mac_header 0x%p\n", mac_header, mac_header - sizeof(custom_option));
    // printk(KERN_INFO "mac_header %02x %02x\n", *mac_header, *(mac_header + 1));
    memcpy(ip_header + ip_hdr_len - sizeof(custom_option), custom_option, sizeof(custom_option));

    // Update pointers and offsets
    // printk(KERN_INFO "old mac header pointer 0x%llx\n", mac_header);
    mac_header -= sizeof(custom_option);
    // printk(KERN_INFO "new mac header pointer 0x%llx\n", mac_header);
    ip_header -= sizeof(custom_option);
    skb->mac_header -= sizeof(custom_option);
    skb->network_header -= sizeof(custom_option);

    // Update IP header
    iph = (struct iphdr *) ip_header;
    iph->ihl = new_ip_hdr_len / 4;
    iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(custom_option));
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    skb->ip_summed = CHECKSUM_UNNECESSARY;
    // skb_checksum_help(skb);
    skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);

    // int i = 0;
    // for( ; i < 44; i = i + 4){
    //     printk("%02x %02x %02x %02x ", *(mac_header + i), *(mac_header + i + 1), *(mac_header + i + 2), *(mac_header + i + 3));
    // }

    // skb->dev = state->out;
    
    return NF_ACCEPT;
}

static unsigned int simple_test_in(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state){
    struct iphdr *iph;
    unsigned char * ip_header;
    int ip_hdr_len;
    // unsigned char custom_option[] = {0x0, 0x0, 0x0, 0x0};

    // Check if the packet is an IP packet
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    ip_header = skb_network_header(skb);
    if (!iph)
        return NF_ACCEPT;

    // Ensure the packet is IPv4
    if (iph->version != 4)
        return NF_ACCEPT;

    // Only affect ICMP packet
    if(iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl * 4;

    iph = (struct iphdr *) ip_header;
    // printk(KERN_INFO "origin iph.ihl %u\n", iph->ihl);
    // printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    // From 192.168.31.150 to 192.168.31.1
    iph->saddr = iph->saddr ^ 0x97000000;
    // printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    // printk(KERN_INFO "skb.hdr_len: %d, skb.len: %d, skb.data_len: %d, skb network header len: %d\n", skb->hdr_len, skb->len, skb->data_len, skb_network_header_len(skb));
    iph->ttl = 64;
    // iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(custom_option));
    // printk(KERN_INFO "ttl before: %u\n", iph->ttl);
    // iph->ttl = 64;
    // printk(KERN_INFO "ttl after: %u\n", iph->ttl);
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    // printk(KERN_INFO "new checksum: 0x%x\n", iph->check);
    

    // skb_checksum_help(skb);
    // skb->ip_summed = CHECKSUM_NONE;

    return NF_ACCEPT;
}

static unsigned int simple_test_out(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state){
    struct iphdr *iph;
    unsigned char * ip_header;
    int ip_hdr_len;
    // unsigned char custom_option[] = {0x0, 0x0, 0x0, 0x0};

    // Check if the packet is an IP packet
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    ip_header = skb_network_header(skb);
    if (!iph)
        return NF_ACCEPT;

    // Ensure the packet is IPv4
    if (iph->version != 4)
        return NF_ACCEPT;

    // Only affect ICMP packet
    if(iph->protocol != IPPROTO_ICMP && iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    ip_hdr_len = iph->ihl * 4;

    iph = (struct iphdr *) ip_header;
    // printk(KERN_INFO "origin iph.ihl %u\n", iph->ihl);
    // printk(KERN_INFO "IP header: original dest: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
    // iph->daddr = iph->daddr ^ 0x97000000;
    // printk(KERN_INFO "IP header: modified dest: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
    iph->ttl = 32;
    // iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(custom_option));
    // printk(KERN_INFO "ttl before: %u\n", iph->ttl);
    // iph->ttl = 64;
    // printk(KERN_INFO "ttl after: %u\n", iph->ttl);
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    // printk(KERN_INFO "new checksum: 0x%x\n", iph->check);
    

    //skb_checksum_help(skb);
    skb->ip_summed = CHECKSUM_NONE;

    return NF_ACCEPT;
}

static int __init mod_init(void) {
    nfho.hook = add_opts_to_iph_out; // Hook function
    nfho.hooknum = NF_INET_PRE_ROUTING; // Hook at the pre-routing point
    nfho.pf = PF_INET; // IPv4 packets
    nfho.priority = NF_IP_PRI_FIRST; // First priority

    // _nfho.hook = simple_test_out;
    // _nfho.hooknum = NF_INET_POST_ROUTING;
    // _nfho.pf = PF_INET;
    // _nfho.priority = NF_IP_PRI_FIRST;

    if(nf_register_net_hook(&init_net, &nfho)){
        printk(KERN_ERR"nf_register_net_hook() failed\n");
        return -1;
    }

    //if(nf_register_net_hook(&init_net, &_nfho)){
    //    printk(KERN_ERR"nf_register_net_hook() failed\n");
    //    return -1;
    //}
    return 0;
}

static void __exit mod_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    //nf_unregister_net_hook(&init_net, &_nfho);
}

module_init(mod_init);
module_exit(mod_exit);
