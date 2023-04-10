/*
Andreas Demosthenous
1022308

Minimal GDB
*/

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* C++ libs*/
#include <iostream>
#include <vector>

/*libelf*/
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>

// capstone
#include <capstone/capstone.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#define TOOL "mdb"

#define die(...)                                \
    do                                          \
    {                                           \
        fprintf(stderr, TOOL ": " __VA_ARGS__); \
        fputc('\n', stderr);                    \
        exit(EXIT_FAILURE);                     \
    } while (0)

struct Breakpoint
{
    int id;
    long address;
    long original_instruction;
};

void print_menu(){

    printf("\t Minimal GDB\n");
    printf("\n  1. b (set breakpoint)\n     e.g. b foo\n\n  2. l(list breakpoints)\n\n  3. d(remove breakpoint)\n     e.g. d 1\n\n  4. r(start execution)\n\n  5. c(continue execution)\n  6. si(step into)\n\n  7. disas(disassemble current instruction)\n\n  8. ri(list registers)\n\n  9. disas+(disassemble given address/symbol)\n     e.g. disas+ foo\n\n");
}

// converts char to int safely
int to_int(char *str)
{
    char *endptr;
    errno = 0;
    long num = strtol(str, &endptr, 10);
    if (errno != 0 || *endptr != '\0')
    {
        printf(" - Error: %s is not a valid id\n", str);
        return -1;
    }
    return num;
}

// reads next input space seperated(max is 127 bytes to avoid overflow)
char *read_next()
{
    // command can be max 128 bytes
    char *command = (char *)malloc(128 * sizeof(char));

    printf(" > ");
    scanf(" %127s", command);
    return command;
}

// steps to the next instruction
void process_step(int pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

// searches in a given section scn in the given elf with a given symbol name
long search_section(char *symbol_name, Elf *elf, Elf_Scn *scn)
{

    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        die("(getshdr) %s", elf_errmsg(-1));

    // gets the contents of the section
    data = elf_getdata(scn, NULL);

    // gets the amount of entries(symbols)
    count = shdr.sh_size / shdr.sh_entsize;

    // iterating the scn contents
    for (int i = 0; i < count; ++i)
    {
        GElf_Sym sym;

        // Retrieves the symbol with i index
        gelf_getsym(data, i, &sym);

        char *symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
        if (strncmp(symname, symbol_name, 128) == 0)
        {
            // symbol found
            printf("\n - Symbol %s found at: 0x%lx\n", symname, (long)sym.st_value);
            return (long)sym.st_value;
        }
    }
    return (long)-1;
}

// locates .symtab section and saves it in the symtab reference
void locate_symtab(char *filename, Elf **elf, Elf_Scn **symtab)
{

    bool symtab_found = 0;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        die("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!*elf)
        die("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(*elf, &shstrndx) != 0)
        die("(getshdrstrndx) %s", elf_errmsg(-1));

    // iterating sections to find .symtab
    int s_index = 0;
    while ((scn = elf_nextscn(*elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            die("(getshdr) %s", elf_errmsg(-1));
        s_index++;

        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(*elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            *symtab = scn;
            symtab_found = 1;
        }
    }
    // If .symtab section is found => Binary is not stripped =>
    if (!symtab_found)
    {
        *symtab = NULL;
    }
}

// returns the address of the given symbol name from the .symtab section
long get_symbol_addr(char *symbol_name, Elf *elf, Elf_Scn *symtab)
{
    // search in the symbol table
    long sym_addr;
    if (symtab != NULL && (sym_addr = search_section(symbol_name, elf, symtab)) != (long)-1)
    {
        return (long)sym_addr;
    }
    return (long)-1;
}

// searches the breakpoints for a bp in the given address and saves the result in the current_bp reference
int get_current_bp(long current_address, std::vector<Breakpoint> &breakpoints, Breakpoint **current_bp)
{

    // iterates breakpoints
    for (std::vector<Breakpoint>::iterator it = breakpoints.begin(); it != breakpoints.end(); ++it)
    {
        Breakpoint &bp = *it;

        if (bp.address == current_address)
        { // breakpoint found!
            *current_bp = &bp;
            return 1;
        }
    }

    return 0;
}

// sets a breakpoint at the given address in the process with the given pid
long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
    {
        return (long)-1;
    }

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        return (long)-1;

    // breakpoint added succesfully!
    return previous_code;
}

// When a breakpoint is hit. The original code(fixed to 32 bits) has to be restored. This can cause
// nearby breakpoints (int3 - 0xCC) to be overwritten and get lost.
// This method resets the nearby breakpoints of the given bp
void fix_nearby_breakpoints(int pid, Breakpoint *current_bp, std::vector<Breakpoint> &breakpoints)
{
    long start = current_bp->address + 1;
    long end = current_bp->address + 32;
    while (start < end)
    {

        if (get_current_bp(start, breakpoints, &current_bp))
        { // nearby breakpoint found in the breakpoints vector ->
          // probably overwritten -> reset it to ensure it doesnt get lost
            set_breakpoint(pid, start);
            break;
        }
        start++;
    }
}

// Serves the currenly hit breakpoint
void serve_breakpoint(int pid, std::vector<Breakpoint> &breakpoints)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    long current_rip = regs.rip;
    Breakpoint *current_bp;

    // when the breakpoint is hit (INT3 - 0xCC executes), rip moves to the next instruction
    // 1 byte next, so I have to check rip-1 to find the currently hit breakpoint
    int found = get_current_bp(current_rip - 1, breakpoints, &current_bp);
    if (!found)
    {
        return;
    }
    printf(" - Breakpoint hit at : 0x%lx\n", current_bp->address);

    long original_instruction = current_bp->original_instruction;

    // Moving rip back at the start of the breakpoint
    regs.rip--;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));

    // restoring the original instruction where the int3 was before
    if (ptrace(PTRACE_POKEDATA, pid, (void *)current_bp->address, (void *)current_bp->original_instruction) == -1)
        die("(pokedata) %s", strerror(errno));

    // fixing nearby breakpoints
    fix_nearby_breakpoints(pid, current_bp, breakpoints);
    return;
}

// prints the breakpoints
void print_breakpoints(std::vector<Breakpoint> &breakpoints)
{
    for (Breakpoint bp : breakpoints)
    {
        printf(" - %d. 0x%lx\n", bp.id, bp.address);
    }
}

// removes a breakpoint with the given id
bool remove_breakpoint(int id, int pid, std::vector<Breakpoint> &breakpoints)
{
    for (std::vector<Breakpoint>::iterator it = breakpoints.begin(); it != breakpoints.end(); ++it)
    {
        Breakpoint &bp = *it;
        if (bp.id == id)
        {
            // restores the original instruction
            if (ptrace(PTRACE_POKEDATA, pid, (void *)bp.address, (void *)bp.original_instruction) == -1)
                die("(pokedata) %s", strerror(errno));

            // fixing the breakpoints in addresses after the current breakpoint since
            // restoring the current breakpoint might have caused overwriting of a nearby breakpoint
            fix_nearby_breakpoints(pid, &bp, breakpoints);

            // removing it from the vector
            breakpoints.erase(it);
            return true;
        }
    }
    return false;
}

// performs disassembly of the process with the given pid starting from the given address
void disas(csh handle, int pid, long starting_addr)
{
    // initializing a buffer to store all the instructions we want to disasemble
    unsigned char ins_buf[1024];
    for (int i = 0; i < 10; i++)
    {
        // getting the next address
        long addr = starting_addr + i * sizeof(long);
        long next_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);

        if (next_inst == -1 && errno)
        {
            fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
            return;
        }
        // copying the instruction in the buffer
        memcpy(&ins_buf[i * sizeof(long)], &next_inst, sizeof(long));
    }

    cs_insn *insn;
    size_t count;

    // amount of instructions
    count = cs_disasm(handle, ins_buf, 32, 0x0, 0, &insn);

    if (count > 0)
    {
        size_t j;
        // disasembling the next 10 instructions
        for (j = 0; j < count && j < 10; j++)
        {
            // print symbolic repr. of current instruction
            fprintf(stderr, "0x%" PRIx64 ": %-10s %-10s\n", starting_addr + insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);

            // stopping on the end of function(ret)
            if (insn[j].id == X86_INS_RET)
                break;
        }
        cs_free(insn, count);
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

// prints current registers values of given process pid
void print_registers(int pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    printf("RIP:  0x%llx\nRBP:  0x%llx\nRSP:  0x%llx\nRBX:  0x%llx\nRAX:  0x%llx\nRCX:  0x%llx\nRDX:  0x%llx\nRSI:  0x%llx\nRDI:  0x%llx\nR8:  0x%llx\nR9:  0x%llx\nR10:  0x%llx\nR11:  0x%llx\nR12:  0x%llx\nR13:  0x%llx\nR14:  0x%llx\nR15:  0x%llx\nEFLAGS:  0x%llx\n",
           regs.rip, regs.rbp, regs.rsp, regs.rbx, regs.rax, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.r8,
           regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.eflags);
}

// method handling the given command of the user
bool process_op(csh handle, char *op, int pid, std::vector<Breakpoint> &breakpoints, Elf *elf, Elf_Scn *symtab, bool &started)
{
    // breakpoints cnt to use for the ids
    static int breakpoints_cnt = 1;

    // waitpid status
    int signal_status;

    if (strcmp(op, "b") == 0)
    { // add breakpoints
        char *target = read_next();
        if (target[0] == '*')
        {
            // breakpoint by address
            long addr;
            sscanf(target + 1, "%lx", &addr);

            // check if bp already exists
            Breakpoint *current_bp;
            if (get_current_bp(addr, breakpoints, &current_bp))
            {
                printf("Breakpoint at : 0x%lx already exists\n", addr);
                return true;
            }

            // set bp
            long original_instruction = set_breakpoint(pid, addr);

            // ensuring bp is added succesfully
            if (original_instruction == (long)-1)
            {
                printf(" - Coulden't add breakpoint at 0x%lx\n", addr);
                return true;
            }

            // add bp in the vector
            Breakpoint bp = {breakpoints_cnt++, addr, original_instruction};
            breakpoints.push_back(bp);

            printf(" - Breakpoint %d at 0x%lx\n", bp.id, bp.address);
        }
        else
        {
            // breakpoint by symbol name
            long addr = get_symbol_addr(target, elf, symtab);
            if (addr == (long)-1)
            {
                printf(" - Symbol %s not found\n", target);
                return true;
            }

            Breakpoint *current_bp;
            if (get_current_bp(addr, breakpoints, &current_bp))
            {
                printf(" - Breakpoint at : %lx already exists\n", addr);
                return true;
            }

            long original_instruction = set_breakpoint(pid, addr);

            // ensuring bp is added succesfully
            if (original_instruction == (long)-1)
            {
                printf(" - Coulden't add breakpoint at %lx\n", addr);
                return true;
            }

            struct Breakpoint bp = {breakpoints_cnt++, addr, original_instruction};
            breakpoints.push_back(bp);

            printf(" - Breakpoint %d at 0x%lx\n", bp.id, bp.address);
        }
    }
    else if (strcmp(op, "l") == 0)
    {
        print_breakpoints(breakpoints);
    }
    else if (strcmp(op, "d") == 0)
    {
        char *target_id = read_next();
        int id = to_int(target_id);
        if (id < 0)
        {
            return true;
        }
        else
        {
            if (remove_breakpoint(id, pid, breakpoints))
            {
                printf(" - Breakpoint %d removed\n", id);
            }
            else
            {
                printf(" - Breakpoint %d not found\n", id);
            }
        }
    }
    else if (strcmp(op, "r") == 0)
    {
        if (started)
        {
            printf(" -  Binary already running!\n");
            return true;
        }

        // continue execution
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            die("(cont) %s", strerror(errno));
        // wait for signal
        waitpid(pid, &signal_status, 0);

        if (!WIFSTOPPED(signal_status))
        {
            // child process exited normally
            return false;
        }

        // serves hit breakpoint
        serve_breakpoint(pid, breakpoints);

        // get current instruction address (rip)
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        long current_rip = regs.rip;

        // disassemble starting from rip
        disas(handle, pid, current_rip);

        started = true;
    }
    else if (strcmp(op, "c") == 0)
    {
        if (!started)
        {
            printf(" - Error, binary not started\n");
            return true;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        long current_rip = regs.rip;

        Breakpoint *current_bp;
        // if continueing from a breakpoint:
        int found = get_current_bp(current_rip, breakpoints, &current_bp);

        // if the executed instruction is set as breakpoint, put it back.
        if (found)
        { // proceeding to the next instruction
            process_step(pid);

            // setting back the bp to the previous instruction (old rip)
            set_breakpoint(pid, current_rip);
        }

        // continue to the next bp
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            die("(cont) %s", strerror(errno));
        waitpid(pid, &signal_status, 0);

        if (!WIFSTOPPED(signal_status))
        {
            // child process exited normally
            return false;
        }
        serve_breakpoint(pid, breakpoints);
    }
    else if (strcmp(op, "si") == 0)
    {
        // bool bp_restored = true;

        if (!started)
        {
            printf(" - Error, binary not started\n");
            return true;
        }

        // get current instr(rip)
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        long current_rip = regs.rip;

        Breakpoint *current_bp;
        int found = get_current_bp(current_rip, breakpoints, &current_bp);

        // executes next instruction
        process_step(pid);

        // if the previous instruction is set as breakpoint, put it back.
        if (found)
        {
            set_breakpoint(pid, current_rip);
        }

        // get current instr(rip)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        current_rip = regs.rip;

        found = get_current_bp(current_rip, breakpoints, &current_bp);

        // if the current instruction is set as breakpoint
        if (found)
        {
            printf(" - Breakpoint hit at : 0x%lx\n", current_bp->address);
            long original_instruction = current_bp->original_instruction;

            // restoring the original instruction where the int3 was before
            if (ptrace(PTRACE_POKEDATA, pid, (void *)current_bp->address, (void *)current_bp->original_instruction) == -1)
                die("(pokedata) %s", strerror(errno));
        }
    }
    else if (strcmp(op, "ri") == 0)
    {
        if (!started)
        {
            printf(" - Error, binary not started\n");
            return true;
        }
        print_registers(pid);
    }
    else if (strcmp(op, "disas") == 0)
    {
        if (!started)
        {
            printf(" - Error, binary not started\n");
            return true;
        }

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            die("(getregs) %s", strerror(errno));

        long current_rip = regs.rip;

        disas(handle, pid, current_rip);
    }
    else if (strcmp(op, "disas+") == 0)
    { // disassemble starting from a given address or symbol name
        char *target = read_next();
        if (target[0] == '*')
        {
            // disas by address
            long addr;
            sscanf(target + 1, "%lx", &addr);

            // disas starting from given address
            disas(handle, pid, addr);
        }
        else
        {
            // breakpoint by symbol name
            long addr = get_symbol_addr(target, elf, symtab);
            if (addr == (long)-1)
            {
                printf(" - Symbol %s not found\n", target);
                return true;
            }

            disas(handle, pid, addr);
        }
    }
    else
    {
        printf(" - Invalid command\n");
    }
    return true;
}

int main(int argc, char **argv)
{
    // vector to keep the breakpoints
    std::vector<Breakpoint> breakpoints;

    if (argc <= 1)
        die("mdb <program>: %d", argc);
    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* error */
        die("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */
        execvp(argv[1], argv + 1);
        die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    // init capstone
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    Elf_Scn *symtab;
    Elf *elf;

    // locate symbols (.symtab) for later to be used to locate
    // the symbols used by the user.
    locate_symtab(argv[1], &elf, &symtab);

    // command can be at least 128 bytes(characters long)
    char *command;

    // while loop to wait and read user's commands
    bool running = true, started = false;

    print_menu();

    while (running)
    {
        // reads the operator(b, c, r, etc)
        char *op = read_next();
        running = process_op(handle, op, pid, breakpoints, elf, symtab, started);

        free(op);
    }
}
