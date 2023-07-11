#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

void setup_page_tables(void* mem, struct kvm_sregs* sregs)
{
    uint64_t pml4_addr = 0x1000;
    uint64_t* pml4 = (void*)(mem + pml4_addr);

    uint64_t pdpt_addr = 0x2000;
    uint64_t* pdpt = (void*)(mem + pdpt_addr);

    uint64_t pd_addr = 0x3000;
    uint64_t* pd = (void*)(mem + pd_addr);

    pml4[0] = 3 | pdpt_addr; // PDE64_PRESENT | PDE64_RW | pdpt_addr
    pdpt[0] = 3 | pd_addr;   // PDE64_PRESENT | PDE64_RW | pd_addr
    pd[0] = 3 | 0x80;        // PDE64_PRESENT | PDE64_RW | PDE64_PS

    sregs->cr3 = pml4_addr;
    sregs->cr4 = 1 << 5;     // CR4_PAE;
    sregs->cr4 |= 0x600;     // CR4_OSFXSR | CR4_OSXMMEXCPT; enable SSE instruction
    sregs->cr0 = 0x80050033; // CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
    sregs->efer = 0x500;     // EFER_LME | EFER_LMA
}

void setup_segment_registers(struct kvm_sregs* sregs)
{
    struct kvm_segment seg = {
        .base = 0,
        .limit = 0xffffffff,
        .selector = 1 << 3,
        .present = 1,
        .type = 11, /* execute, read, accessed */
        .dpl = 0,   /* privilege level 0 */
        .db = 0,
        .s = 1,
        .l = 1,
        .g = 1,
    };
    sregs->cs = seg;
    seg.type = 3; /* read/write, accessed */
    seg.selector = 2 << 3;
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

int kvm(uint8_t code[], size_t code_len)
{
    /* open KVM device */
    int kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

    /* create VM */
    int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);

    /* set up user memory region */
    size_t mem_size = 0x40000000; // size of user mem (40Mb)
    void* mem = mmap(0, mem_size,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    int user_entry = 0x0;
    memcpy((void*)((size_t)mem + user_entry), code, code_len);
    struct kvm_userspace_memory_region region = {
        .slot = 0, /* memory mapping slot */
        .flags = 0,
        .guest_phys_addr = 0, /* physical aspect of guest */
        .memory_size = mem_size,
        .userspace_addr = (size_t)mem
    };
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

    /* create vCPU */
    int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);

    /* setup memory for vCPU */
    size_t vcpu_mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    struct kvm_run* run = (struct kvm_run*)mmap(0,
        vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);

    /* set up vCPU's registers */
    struct kvm_regs regs;
    ioctl(vcpufd, KVM_GET_REGS, &regs);
    regs.rip = 0;
    regs.rsp = 0x200000;                // stack address
    regs.rflags = 0x2;                  // in x86 the 0x2 bit should always be set
    ioctl(vcpufd, KVM_SET_REGS, &regs); // set registers

    /* special registers include segment registers */
    struct kvm_sregs sregs;
    ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    /* enable page table */
    setup_page_tables(mem, &sregs);
    setup_segment_registers(&sregs);
    ioctl(vcpufd, KVM_SET_SREGS, &sregs);

    /* execute code */
    while (1) {
        ioctl(vcpufd, KVM_RUN, NULL);
        switch (run->exit_reason) {
        case KVM_EXIT_HLT:
            fputs("KVM_EXIT_HLT", stderr);
            return 0;
        case KVM_EXIT_IO:
            /* TODO: check port and direction here */
            putchar(*(((char*)run) + run->io.data_offset));
            break;
        case KVM_EXIT_FAIL_ENTRY:
            errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                run->fail_entry.hardware_entry_failure_reason);
        case KVM_EXIT_INTERNAL_ERROR:
            errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
                run->internal.suberror);
        case KVM_EXIT_SHUTDOWN:
            errx(1, "KVM_EXIT_SHUTDOWN");
        default:
            errx(1, "Unhandled reason: %d", run->exit_reason);
        }
    }
    return 0;
}

int main()
{
    /*
     * Real mode
     * .code16
     * mov al, 0x61
     * mov dx, 0x217
     * out dx, al
     * mov al, 10
     * out dx, al
     * hlt
     * */
    // uint8_t code[] = "\xB0\x61\xBA\x17\x02\xEE\xB0\n\xEE\xF4";

    /*
     * Long mode
     * movabs rax, 0x0a33323144434241
     * push 8
     * pop rcx
     * mov edx, 0x217
     *
     * OUT:
     * out dx, al
     * shr rax, 8
     * loop OUT
     * hlt
     * */
    uint8_t code[] = "H\xB8\x41\x42\x43\x44\x31\x32\x33\nj\bY\xBA\x17\x02\x00\x00\xEEH\xC1\xE8\b\xE2\xF9\xF4";
    return kvm(code, sizeof(code));
}
