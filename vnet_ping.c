#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/kmod.h>
#include <net/ip.h>

#define DRV_NAME "vnet_ping"
#define PROC_NAME "vnet_ping_ip"

static struct net_device *vnet_dev = NULL;
static __be32 vnet_ip = 0;
static struct proc_dir_entry *proc_entry = NULL;
static DEFINE_MUTEX(vnet_mutex);

static void set_unique_mac(struct net_device *dev)
{
    enum
    {
        GENERATE_TRIES_COUNT_MAX = 100,
    };

    u8 mac[ETH_ALEN] = {0};
    bool collision = false;
    int retries = 0;
    struct net_device *iter = NULL;

    do
    {
        collision = false;
        eth_random_addr(mac);
        /* IEEE 802: locally administered (bit 1) & unicast (bit 0) */
        mac[0] = (mac[0] & 0xFE) | 0x02;

        rcu_read_lock();
        for_each_netdev_rcu(&init_net, iter)
        {
            if (ether_addr_equal(mac, iter->dev_addr))
            {
                collision = true;
                break;
            }
        }
        rcu_read_unlock();

        if (!collision)
        {
            eth_hw_addr_set(dev, mac);
            dev->addr_assign_type = NET_ADDR_RANDOM;
            return;
        }
        retries++;
    } while (retries < GENERATE_TRIES_COUNT_MAX);

    eth_hw_addr_random(dev);
}

static int assign_ip_via_umh(struct net_device *dev, __be32 ip)
{
    enum
    {
        CMD_SIZE = 256,
        IP_STR_SIZE = 16,
    };

    char cmd[CMD_SIZE] = {0};
    char ip_str[IP_STR_SIZE] = {0};
    int ret = 0;

    snprintf(ip_str, sizeof(ip_str), "%pI4", &ip);
    snprintf(cmd, sizeof(cmd), "/usr/sbin/ip addr flush dev %s >/dev/null 2>&1 && /usr/sbin/ip addr add %s/32 dev %s scope host",
        dev->name, ip_str, dev->name);

    ret = call_usermodehelper("/bin/sh", (char *[]){"sh", "-c", cmd, NULL}, NULL, UMH_WAIT_PROC);
    if (ret)
    {
        pr_warn("%s: UMH exit code %d. CMD: %s\n", DRV_NAME, ret, cmd);
    }

    return ret;
}

static netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    enum
    {
        TTL_VALUE = 64,
    };

    if (vnet_ip == 0 || !vnet_dev)
    {
        kfree_skb(skb);
        dev->stats.tx_dropped++;
        return NETDEV_TX_OK;
    }

    struct ethhdr *eth = eth_hdr(skb);
    if (ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = ip_hdr(skb);
        if (iph->daddr == vnet_ip && iph->protocol == IPPROTO_ICMP)
        {
            struct icmphdr *icmph = icmp_hdr(skb);
            if (icmph->type == ICMP_ECHO)
            {
                struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
                if (nskb)
                {
                    struct ethhdr *neth = eth_hdr(nskb);
                    struct iphdr *niph = ip_hdr(nskb);
                    struct icmphdr *nicmph = icmp_hdr(nskb);
                    u8 tmp_mac[ETH_ALEN] = {0};
                    __be32 tmp_ip = 0;

                    ether_addr_copy(tmp_mac, neth->h_source);
                    ether_addr_copy(neth->h_source, neth->h_dest);
                    ether_addr_copy(neth->h_dest, tmp_mac);

                    tmp_ip = niph->saddr;
                    niph->saddr = niph->daddr;
                    niph->daddr = tmp_ip;

                    niph->ttl = TTL_VALUE;
                    niph->tos = 0;
                    niph->frag_off = 0;
                    ip_send_check(niph);

                    nicmph->type = ICMP_ECHOREPLY;
                    nicmph->code = 0;
                    nicmph->checksum = 0;
                    nicmph->checksum = csum_fold(csum_partial(nicmph,
                        nskb->len - (ETH_HLEN + niph->ihl * 4), 0));

                    nskb->protocol = htons(ETH_P_IP);
                    nskb->dev = vnet_dev;
                    nskb->pkt_type = PACKET_HOST;

                    vnet_dev->stats.rx_packets++;
                    vnet_dev->stats.rx_bytes += nskb->len;
                    netif_rx(nskb);
                }
                kfree_skb(skb);
                dev->stats.tx_packets++;
                dev->stats.tx_bytes += skb->len;

                return NETDEV_TX_OK;
            }
        }
    }
    kfree_skb(skb);
    dev->stats.tx_dropped++;

    return NETDEV_TX_OK;
}

static const struct net_device_ops vnet_netdev_ops = {
    .ndo_start_xmit = vnet_start_xmit,
};

static void remove_iface(void)
{
    mutex_lock(&vnet_mutex);
    if (vnet_dev)
    {
        unregister_netdev(vnet_dev);
        free_netdev(vnet_dev);
        vnet_dev = NULL;
    }
    mutex_unlock(&vnet_mutex);
}

static ssize_t vnet_proc_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *pos)
{
    enum
    {
        KBUF_SIZE = 64,
        MTU = 1500,
    };

    char kbuf[KBUF_SIZE] = {0};
    char *trimmed_kbuf = NULL;
    bool iface_state = false;
    __be32 new_ip = 0;
    int ret = 0;

    if (count >= sizeof(kbuf))
    {
        count = sizeof(kbuf) - 1;
    }
    if (copy_from_user(kbuf, buf, count))
    {
        return -EFAULT;
    }
    kbuf[count] = '\0';

    trimmed_kbuf = strstrip(kbuf);

    if (in4_pton(trimmed_kbuf, -1, (u8 *)&new_ip, -1, NULL) != 1)
    {
        if (kstrtobool(kbuf, &iface_state))
        {
            return -EINVAL;
        }

        if (!iface_state)
        {
            remove_iface();
            return count;
        }
        else
        {
            return -EINVAL;
        }
    }

    mutex_lock(&vnet_mutex);

    if (!vnet_dev)
    {
        vnet_dev = alloc_netdev(0, DRV_NAME, NET_NAME_UNKNOWN, ether_setup);
        if (!vnet_dev)
        {
            mutex_unlock(&vnet_mutex);
            return -ENOMEM;
        }

        set_unique_mac(vnet_dev);
        vnet_dev->netdev_ops = &vnet_netdev_ops;
        vnet_dev->flags |= IFF_NOARP;
        vnet_dev->mtu = MTU;

        ret = register_netdev(vnet_dev);
        if (ret)
        {
            free_netdev(vnet_dev);
            vnet_dev = NULL;
            mutex_unlock(&vnet_mutex);
            pr_err("%s: register_netdev failed: %d\n", DRV_NAME, ret);
            return ret;
        }
        pr_info("%s: Netdevice %s registered.\n", DRV_NAME, DRV_NAME);
    }

    vnet_ip = new_ip;

    rtnl_lock();
    dev_change_flags(vnet_dev, vnet_dev->flags | IFF_UP, NULL);
    rtnl_unlock();

    ret = assign_ip_via_umh(vnet_dev, vnet_ip);
    mutex_unlock(&vnet_mutex);

    if (ret == 0)
    {
        pr_info("%s: IPv4 %pI4 successfully assigned.\n", DRV_NAME, &vnet_ip);
    }
    else
    {
        pr_err("%s: IP assignment failed (code %d). Check /usr/sbin/ip availability.\n", DRV_NAME, ret);
    }

    return count;
}

static ssize_t vnet_proc_read(struct file *file, char __user *buf,
                              size_t count, loff_t *pos)
{
    enum
    {
        KBUF_SIZE = 64,
    };

    char kbuf[KBUF_SIZE] = {0};
    int len = 0;

    if (*pos > 0)
    {
        return 0;
    }

    len = snprintf(kbuf, sizeof(kbuf), "%pI4\n", &vnet_ip);
    if (copy_to_user(buf, kbuf, len))
    {
        return -EFAULT;
    }

    *pos = len;
    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vnet_proc_ops = {
    .proc_read  = vnet_proc_read,
    .proc_write = vnet_proc_write,
};
#else
static const struct file_operations vnet_proc_fops = {
    .owner = THIS_MODULE,
    .read  = vnet_proc_read,
    .write = vnet_proc_write,
};
#endif

static int __init vnet_init(void)
{
    vnet_ip = 0;
    vnet_dev = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &vnet_proc_ops);
#else
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &vnet_proc_fops);
#endif
    if (!proc_entry)
    {
        pr_err("%s: proc_create failed\n", DRV_NAME);
        return -ENOMEM;
    }

    pr_info("%s: loaded. Write IP to /proc/%s to create interface.\n", DRV_NAME, PROC_NAME);
    return 0;
}

static void __exit vnet_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    remove_iface();
    pr_info("%s: unloaded.\n", DRV_NAME);
}

module_init(vnet_init);
module_exit(vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dreinhitser");
MODULE_DESCRIPTION("Lazy-init virtual netdev with robust IP replacement via procfs");
