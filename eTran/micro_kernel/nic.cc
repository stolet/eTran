#include "nic.h"

#include <dirent.h>
#include <fstream>
#include <ifaddrs.h>
#include <sched.h>
#include <string>
#include <algorithm>

#include <netinet/in.h>

#include <utils/utils.h>

/* mlx5 XDP transmission selects its queue by the current CPU number.
 * Queue zero exists for every supported NIC configuration. */
static int pin_pacer(void)
{
    DIR *tasks = opendir("/proc");
    if (tasks == nullptr)
    {
        perror("open /proc for pacer affinity");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(tasks)) != nullptr)
    {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        std::ifstream comm(std::string("/proc/") + entry->d_name + "/comm");
        std::string name;
        if (!std::getline(comm, name) || name != "bpf_pacer")
            continue;

        pid_t pid = static_cast<pid_t>(strtol(entry->d_name, nullptr, 10));
        cpu_set_t cpus;
        CPU_ZERO(&cpus);
        CPU_SET(0, &cpus);
        int ret = sched_setaffinity(pid, sizeof(cpus), &cpus);
        if (ret != 0)
            perror("set bpf_pacer affinity");
        closedir(tasks);
        return ret;
    }

    closedir(tasks);
    fprintf(stderr, "Cannot find bpf_pacer; boot the eTran kernel first\n");
    return -1;
}

static int enable_napi_polling(std::string if_name)
{
    std::string cmd1 = "echo 200 > /sys/class/net/" + if_name + "/gro_flush_timeout";
    std::string cmd2 = "echo 100 > /sys/class/net/" + if_name + "/napi_defer_hard_irqs";
    if (!exec_cmd(cmd1) || !exec_cmd(cmd2))
    {
        fprintf(stderr, "Failed to enable napi polling\n");
        return -1;
    }
    return 0;
}

static void disable_napi_polling(std::string if_name)
{
    std::string cmd1 = "echo 0 > /sys/class/net/" + if_name + "/gro_flush_timeout";
    std::string cmd2 = "echo 0 > /sys/class/net/" + if_name + "/napi_defer_hard_irqs";
    if (!exec_cmd(cmd1) || !exec_cmd(cmd2))
    {
        fprintf(stderr, "Failed to enable napi polling\n");
        exit(EXIT_FAILURE);
    }
    printf("disable napi polling\n");
}

static int set_affinity(std::string pcie_name)
{
    std::string cmd;
    cmd = "cat /proc/interrupts | grep " + pcie_name + " | awk 'NR > 1 {print $1}' | sed 's/://'";
    std::string res;
    std::vector<int> irq_list;
    exec_cmd(cmd, res);
    if (res.empty())
    {
        fprintf(stderr, "Failed to get IRQ list\n");
        return -1;
    }

    std::string delimiter = "\n";
    size_t pos = 0;
    std::string token;
    while ((pos = res.find(delimiter)) != std::string::npos)
    {
        token = res.substr(0, pos);
        irq_list.push_back(std::stoi(token));
        res.erase(0, pos + delimiter.length());
    }

    unsigned int affinity_value = 1;
    for (int irq : irq_list)
    {
        std::stringstream ss;
        ss << "echo " << std::setw(5) << std::setfill('0') << std::hex << affinity_value
           << " > /proc/irq/" << std::dec << irq << "/smp_affinity";

        std::string cmd = ss.str();

        if (!exec_cmd(cmd))
        {
            std::cerr << "Failed to configure IRQ affinity for IRQ " << irq << std::endl;
            return -1;
        }

        affinity_value <<= 1;
    }
    return 0;
}

static int check_nic(std::string if_name, unsigned int num_queues, std::string &pcie_name)
{
    std::string cmd;
    std::string res;

    cmd = "ethtool -i " + if_name + " | grep 'bus-info' | awk '{print $2}'";
    pcie_name.clear();
    exec_cmd(cmd, pcie_name);
    if (pcie_name.empty())
    {
        fprintf(stderr, "Failed to get PCIE device name for %s\n", if_name.c_str());
        return -1;
    }
    pcie_name.erase(std::remove(pcie_name.begin(), pcie_name.end(), '\n'), pcie_name.end());

    cmd = "ethtool -l " + if_name + " | grep 'Combined' | awk 'NR==1 {print $2}'";
    res.clear();
    exec_cmd(cmd, res);
    unsigned int nic_queues = std::stoi(res);
    if (num_queues > nic_queues)
    {
        fprintf(stderr, "Number of queues is greater than NIC queues (%u > %d)\n", num_queues, nic_queues);
        return -1;
    }
    return 0;
}

/* Get the local IP address of the interface */
static uint32_t getIPAddress(const std::string &if_name)
{
    struct ifaddrs *ifaddr, *ifa;
    uint32_t ip_address = 0; // Default to 0, which could be considered an error value (0.0.0.0).

    if (getifaddrs(&ifaddr) == -1)
    {
        fprintf(stderr, "getifaddrs");
        return ip_address;
    }

    // Walk through the linked list of interfaces
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == nullptr)
            continue;

        // Check for IPv4 family
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            if (if_name == ifa->ifa_name)
            {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)ifa->ifa_addr;
                ip_address = ntohl(ipv4->sin_addr.s_addr); // Network to host long
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return ip_address;
}

int eTranNIC::create_nic(void)
{
    std::string cmd;
    std::string res;
    std::string pcie_name;

    if (check_nic(_if_name, _num_queues, pcie_name))
        return -1;

    /* set the number of NIC queues */
    cmd = "ethtool -L " + _if_name + " combined " + std::to_string(_num_queues);
    if (!exec_cmd(cmd))
    {
        fprintf(stderr, "Failed to configure NIC queues\n");
        return -1;
    }

    if (pin_pacer() != 0)
        return -1;

    /* set the queue length */
    cmd = "ethtool -G " + _if_name + " rx " + std::to_string(_queue_len) + " tx " + std::to_string(_queue_len);
    if (!exec_cmd(cmd))
    {
        fprintf(stderr, "Failed to configure NIC queues\n");
        return -1;
    }

    if (_intr_affinity)
    {
        /* disable irqbalance */
        cmd = "killall irqbalance > /dev/null 2>&1";
        if (!exec_cmd(cmd))
        {
            fprintf(stderr, "Failed to kill irqbalance\n");
            return -1;
        }
        /* set NIC interrupt affinity */
        if (set_affinity(pcie_name))
            return -1;
    }

    if (!_coalescing)
    {
        /* disable NIC coalescing */
        cmd = "ethtool -C " + _if_name + " adaptive-rx off rx-usecs 5 rx-frames 1";
        if (!exec_cmd(cmd))
        {
            fprintf(stderr, "Failed to configure NIC intrs\n");
            return -1;
        }
    }

    if (_napi_polling)
    {
        if (enable_napi_polling(_if_name))
            return -1;
    }

    _local_ip = getIPAddress(_if_name);
    if (_local_ip == 0)
    {
        fprintf(stderr, "Failed to get local IP address\n");
        return -1;
    }

    return 0;
}

void eTranNIC::destroy_nic(void)
{
    if (_napi_polling)
        disable_napi_polling(_if_name);
}
