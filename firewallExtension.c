// **************************************************
// Read me
// **************************************************
// References
// **************************************************
//  - Linux Kernel Development - Robert Love - Pearson Education
//  - Professional Linux Kernel Architecture - Wolfgang Mauerer - Wiley Publishing
//  - E.Ritter, E. Tews, D. Oswald, M. Denzel - University of Birmingham
// **************************************************
// Notes
// **************************************************
// 
// **************************************************

#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/list.h>
#include <linux/proc_fs.h> 
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/namei.h>
#include <net/tcp.h>
#include <asm/uaccess.h>

#define BUFFERSIZE 100
#define PROC_ENTRY_FILENAME "firewallExtension"
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

MODULE_AUTHOR ("1230806");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");

DEFINE_MUTEX(theLock);
DEFINE_MUTEX(devLock);
LIST_HEAD(filterList);

static int deviceOpen = 0;
static struct proc_dir_entry *procFile;

struct entry
{
    unsigned int portNumber;
    unsigned char* program;
    struct list_head list;
};

int Blocked(unsigned int port, unsigned char* program)
{
    // **************************************************
    // Find entry
    // **************************************************
    
    int portRuleExists = 0;
    struct entry* it;
    
    mutex_lock(&theLock);
    
    list_for_each_entry(it, &filterList, list)
    {        
        if(it->portNumber == port)
        {
            portRuleExists = 1;
            
            if(strstr(it->program, program) != NULL)
            {
                printk(KERN_INFO "Firewall filter: Approved - in list");
                mutex_unlock(&theLock);
                return 0;
            }
        }
    }
    
    mutex_unlock(&theLock);
    
    if(portRuleExists)
    {
        printk(KERN_INFO "Firewall filter: Blocked");
        return 1;
    }
    
    printk(KERN_INFO "Firewall filter: Approved - unknown");
    return 0;
}

void EmptyFilterList(void)
{    
    printk(KERN_INFO "Empty filter list \n");
    
    struct entry* it;
    struct entry* tmp;
    
    list_for_each_entry_safe(it, tmp, &filterList, list)
    {
        printk(KERN_INFO "Firewall rule: %u %s \n", it->portNumber, it->program);
        
        kfree(it->program);
        list_del(& it->list);
        
        printk(KERN_INFO "Port no before del: %u \n", it->portNumber);
        kfree(it);
    }

    int isEmpty = list_empty(&filterList);
    printk(KERN_INFO "Is empty: %d \n", isEmpty);
}

void PrintFirewallRules(void)
{    
    struct entry* it;
    list_for_each_entry(it, &filterList, list)
    {
        printk(KERN_INFO "Firewall rule: %u %s", it->portNumber, it->program);
    }
}

void ChangeFilterList(char* localBuffer, size_t count)
{    
    char* portProgramPair = NULL;
    char* token = NULL;
    int portOrProgram = 0;
    
    while( (portProgramPair = strsep(&localBuffer, "\n")) != NULL &&
            *portProgramPair != NULL)
    {
        // printk(KERN_INFO "Found: '%s' : %u \n", portProgramPair, *portProgramPair);
        
        // **************************************************
        // Create new filter entry
        // **************************************************
        struct entry* newEntry = kmalloc(sizeof(struct entry), GFP_KERNEL);
        INIT_LIST_HEAD(& newEntry->list);
        list_add(&newEntry->list, &filterList);
        
        // **************************************************
        // Tokenise port and program
        // **************************************************
        while((token = strsep(&portProgramPair, " ")) != NULL &&
                *token != NULL)
        {
            // printk(KERN_INFO "Split: '%s' : %u \n", token, *token);
            
            if(portOrProgram)
            {
                size_t lengthOfString = strlen(token);                
                newEntry->program = (char*) kmalloc(lengthOfString +1, GFP_KERNEL);
                strcpy(newEntry->program, token);
                
                printk(KERN_INFO "Parsed out program: %s \n", newEntry->program);
                portOrProgram = 0;
            }
            else
            {
                char* after;
                newEntry->portNumber = (unsigned int) simple_strtoul(token, &after, 10);
                
                printk(KERN_INFO "Parsed out port: %u \n", newEntry->portNumber);
                portOrProgram = 1;
            }
        }
    }
}

ssize_t command_handler (struct file *file, 
                         const char __user *buffer, 
                         size_t count, 
                         loff_t *offset) 
{
    // **************************************************
    // Opening debug statements
    // **************************************************
    
    printk (KERN_INFO "Command handler entered\n");
    
    // **************************************************
    // If it's a very short message, it's likely a
    // request to print the filter list
    // **************************************************
    
    if(count <= 2)
    {
        PrintFirewallRules();
        return count;
    }
    
    // **************************************************
    // Otherwise, it will be an updated filter list
    // Copy the buffer into kernel space
    // **************************************************
    
    char* localBuffer = kmalloc(count, GFP_KERNEL);
    if (localBuffer == NULL) 
    {        
        printk(KERN_ERR "Failed to allocate memory (buffer)");
        return -1;
    }

    copy_from_user(localBuffer, buffer, count);
    
    // **************************************************
    // Parse commands and arguments
    // **************************************************
    
    mutex_lock(&theLock);
    
    EmptyFilterList();
    ChangeFilterList(localBuffer, count);
    
    mutex_unlock(&theLock);
    
    kfree(localBuffer);
    
    return count;
}

unsigned int request_handler (const struct nf_hook_ops *ops,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *)) 
{
    struct tcphdr *tcp;
    struct tcphdr _tcph;
    struct sock *sk;
    
    // **************************************************
    // Check if socket has a value
    // **************************************************
    
    sk = skb->sk;
    if (!sk) 
    {
        printk(KERN_ALERT "Firewall pipeline: netfilter called with empty socket!\n");;
        return NF_ACCEPT;
    }
    
    // **************************************************
    // Check the transport protocol is TCP
    // **************************************************
    
    if (sk->sk_protocol != IPPROTO_TCP)
    {
        printk(KERN_ALERT "Firewall pipeline: netfilter called with non-TCP-packet.\n");
        return NF_ACCEPT;
    }

    // **************************************************
    // Get the TCP header for the packet
    // **************************************************

    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp) 
    {
	printk(KERN_ALERT "Firewall pipeline: Could not get tcp-header!\n");
	return NF_ACCEPT;
    }
    
    // **************************************************
    // Check if it's a new or existing connection
    // **************************************************
    
    if (! tcp->syn)
    {
        printk(KERN_INFO "Firewall pipeline: Existing connection. Accepting packet.\n");
        return NF_ACCEPT;
    }
    
    // **************************************************
    // Output layer 3 details
    // **************************************************
    
    struct iphdr *ip = ip_hdr (skb);
    if (!ip) 
    {
        printk(KERN_ALERT "Firewall pipeline: Cannot get IP header!\n!");
    }
    else 
    {
        printk(KERN_INFO "Firewall pipeline: Destination address: %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
    }
    
    printk(KERN_INFO "Firewall pipeline: Destination port: %d\n", ntohs(tcp->dest)); 

    // **************************************************
    // IRQ
    // **************************************************
    
    if (in_irq() || in_softirq()) 
    {
        printk(KERN_ALERT "Firewall pipeline: Not in user context - retry packet\n");
        return NF_ACCEPT;
    }
    
    // **************************************************
    // Get the requesting program
    // **************************************************

    struct path path;
    char cmdlineFile[BUFFERSIZE];
    
    pid_t mod_pid = current->pid;
    snprintf (cmdlineFile, BUFFERSIZE, "/proc/%d/exe", mod_pid); 
    
    int res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
    if (res)
    {
        printk (KERN_ALERT "Firewall pipeline: Could not get dentry for %s!\n", cmdlineFile);
    }
    
    struct dentry *procDentry = path.dentry;
    printk (KERN_INFO "Firewall pipeline: Requesting program: %s\n", procDentry->d_name.name);    
    
    // **************************************************
    // Filter
    // **************************************************
    
    unsigned int portNumber = ntohs(tcp->dest);
    unsigned char* programName = procDentry->d_name.name;
    
    if (Blocked(portNumber, programName)) 
    {
        // Terminate the connection
        tcp_done (sk);
        printk (KERN_INFO "Firewall pipeline: Connection terminated\n");
        path_put(&path);
        return NF_DROP;
    }
    
    path_put(&path);
    return NF_ACCEPT;
}

int procfs_open(struct inode *inode, struct file *file)
{
    mutex_lock(&devLock);
    
    if (deviceOpen)
    {
        mutex_unlock(&devLock);
        return -EAGAIN;
    }
    
    deviceOpen++;
    mutex_unlock(&devLock);
    
    printk (KERN_INFO "procfs_open\n");
    try_module_get(THIS_MODULE);
    return 0;
}

int procfs_close(struct inode *inode, struct file *file)
{
    mutex_lock(&devLock);
    deviceOpen--;
    mutex_unlock(&devLock);

    printk (KERN_INFO "procfs_close\n");
    module_put(THIS_MODULE);
    return 0;
}

const struct file_operations IMPLEMENTED_FILE_OPS = {
    
    .owner   = THIS_MODULE,
    .write   = command_handler,
    .open    = procfs_open,
    .release = procfs_close,
};

static struct nf_hook_ops firewallExtension_ops = {
    
    .hook    = request_handler,
    .pf      = PF_INET,
    .priority= NF_IP_PRI_FIRST,
    .hooknum = NF_INET_LOCAL_OUT
};

int init_module(void)
{
    // **************************************************
    // Opening debug statements
    // **************************************************
    
    printk(KERN_INFO "Initialising kernel module:\n");
    
    // **************************************************
    // Create the /proc file
    // **************************************************
    
    procFile = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &IMPLEMENTED_FILE_OPS, NULL);    
    if (procFile == NULL)
    {
	printk(KERN_ALERT "Error: Could not initialise /proc/%s\n", PROC_ENTRY_FILENAME);
	return -ENOMEM;
    }
    
    // **************************************************
    // Add our handler to the request pipeline
    // **************************************************
    
    int errno = nf_register_hook (&firewallExtension_ops);
    if (errno) 
    {
        printk (KERN_ALERT "Firewall extension could not be registered!\n");
    }
    else 
    {
        printk(KERN_INFO "Firewall extensions module loaded\n");
    }
    
    // **************************************************
    // Closing debug statements
    // **************************************************
    
    printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);
    
    // A non 0 return means init_module failed; module can't be loaded.
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Starting cleanup \n");
    
    // **************************************************
    // Clean up filter list
    // **************************************************
    
    EmptyFilterList();
    
    // **************************************************
    // Remove the netfilter hook
    // **************************************************
    
    nf_unregister_hook (&firewallExtension_ops);
    
    // **************************************************
    // Remove proc entry from proc_fs
    // **************************************************
    
    remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
    
    // **************************************************
    // Closing debug statements
    // **************************************************
    
    printk(KERN_INFO "/proc/%s removed\n", PROC_ENTRY_FILENAME);
    printk(KERN_INFO "Firewall extensions module unloaded\n");
}  

