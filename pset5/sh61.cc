#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>
#include <set>
#include <filesystem>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__


// struct command
//    Data structure describing a command. Add your own stuff.

struct command {
    std::vector<std::string> args;
    pid_t pid = -1;             // process ID running this command, -1 if none

    int infd = STDIN_FILENO;    // FD to map `STDIN_FILENO` onto
    int outpipe[2] = {-1, STDOUT_FILENO};
                                // outbound pipe, `outpipe[0]` is read end
                                //                `outpipe[1]` is write end

    command();
    ~command();

    void run();
};


// command::command()
//    This constructor function initializes a `command` structure. You may
//    add stuff to it as you grow the command structure.

command::command() {
}


// command::~command()
//    This destructor function is called to delete a command.

command::~command() {
}


// fd_count
//    Returns number of open FDs in current process.
//    Only used for assertions and debugging.
//    See citation: `fdcount`

long fd_count() {
  return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),
                       std::filesystem::directory_iterator{});
}


// fd_remap(newfd, oldfd)
//    Remap `oldfd` to `newfd`s file, respecting fd hygiene.

void fd_remap(int newfd, int oldfd) {
    dup2(newfd, oldfd);
    close(newfd);
}


// COMMAND EXECUTION

// command::run()
//    Creates a single child process running the command in `this`, and
//    sets `this->pid` to the pid of the child process.
//
//    If a child process cannot be created, this function should call
//    `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
//    shell or subshell. If this function returns to its caller,
//    `this->pid > 0` must always hold.
//
//    Note that this function must return to its caller *only* in the parent
//    process. The code that runs in the child process must `execvp` and/or
//    `_exit`.
//
//    PHASE 1: Fork a child process and run the command using `execvp`.
//       This will require creating a vector of `char*` arguments using
//       `this->args[N].c_str()`. Note that the last element of the vector
//       must be a `nullptr`.
//    PHASE 4: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PHASE 7: Handle redirections.

void command::run() {

    // Command should be freshly built
    assert(this->pid == -1);
    // Command BNF is never empty
    assert(this->args.size() > 0);
    
    // Fork
    pid_t fork_r = fork();

    // Subshell
    if (fork_r == 0) {

        // Build args vector
        std::vector<char*> cstring_args;
        for (auto elt : this->args) {
            cstring_args.push_back(strdup(elt.c_str()));
        }
        cstring_args.push_back(nullptr);

        // Set up pipes if applicable
        if (this->infd != STDIN_FILENO) fd_remap(this->infd, STDIN_FILENO);
        if (this->outpipe[1] != STDOUT_FILENO) {
            assert(this->outpipe[0] != -1);
            close(this->outpipe[0]);
            fd_remap(this->outpipe[1], STDOUT_FILENO);
        } else assert(this->outpipe[0] == -1);

        // Attempt execution
        int exec_r = execvp(cstring_args[0], cstring_args.data());
        assert(exec_r == -1);
        _exit(EXIT_FAILURE);
    
    // Shell
    } else if (fork_r != -1) {
        this->pid = fork_r;

    // Error
    } else {
        std::cerr << "command::run: failed fork"; 
    }
}


// run_pipeline(pipeline)
//    Run the command *pipeline* contained in `section`.
//    Returns:
//      Success:  exit status of last command in pipeline
//      Fail:     `-1` on missing exit of last command in pipeline
//                `-2` on failed pipe creation

int run_pipeline(shell_parser ppln) {

    // Pipeline BNF is never empty
    auto comm = ppln.first_command();
    assert(comm);

    // Locals
    int command_r;
    std::set<int> children;
    int next_infd = -1;
    int initial_fds = fd_count();

    // Run all commands in the pipeline
    while (comm) {

        // Build next command
        command* c = new command;
        auto tok = comm.first_token();
        while (tok) {
            c->args.push_back(tok.str());
            tok.next();
        }

        // Build pipes if applicable
        if (next_infd != -1) {
            c->infd = next_infd;
            next_infd = -1;
        }
        if (comm.op() == TYPE_PIPE) {
            int pfds[2];
            int pipe_r = pipe(pfds);
            if (pipe_r == -1) return -2;
            c->outpipe[0] = next_infd = pfds[0];
            c->outpipe[1] = pfds[1];
        }

        // Attempt to run command
        c->run();

        // Clean pipes
        if (c->infd != STDIN_FILENO) close(c->infd);
        if (c->outpipe[1] != STDOUT_FILENO) close(c->outpipe[1]);
        else assert(c->outpipe[0] == -1);

        // Add successfully created child to set
        if (c->pid != -1) children.insert(c->pid);
        
        // Free command
        delete c;

        // Iterate
        comm.next_command();
    }

    // Check pipe hygiene
    int current_fds = fd_count();
    assert(initial_fds == current_fds);

    // Wait for all commands in pipeline to exit
    for (auto child : children) waitpid(child, &command_r, WAIT_MYPGRP);

    // Return is based on **last** command
    return WIFEXITED(command_r) ? WEXITSTATUS(command_r) : -1;
}


// run_conditional(cond)
//    Run the *conditional* contained in `section`.

void run_conditional(shell_parser cond) {

    // Conditional BNF is never empty
    auto ppln = cond.first_pipeline();
    assert(ppln);

    // Always run the first pipeline
    bool cond_r = run_pipeline(ppln) == 0;
    int op = ppln.op();
    ppln.next_pipeline();

    // Run post-conditional pipelines
    while (ppln) {
        // If `true && next`, evaluate `next`
        if (op == TYPE_AND && cond_r)
            cond_r &= run_pipeline(ppln) == 0;

        // If `false || next`, evaluate `next`
        else if (op == TYPE_OR && !cond_r)
            cond_r |= run_pipeline(ppln) == 0;
        
        // Iterate
        op = ppln.op();
        ppln.next_pipeline();
    }
}


// run_list(c)
//    Run the command *list* contained in `section`.
//
//    PHASE 1: Use `waitpid` to wait for the command started by `c->run()`
//        to finish.
//
//    The remaining phases may require that you introduce helper functions
//    (e.g., to process a pipeline), write code in `command::run`, and/or
//    change `struct command`.
//
//    It is possible, and not too ugly, to handle lists, conditionals,
//    *and* pipelines entirely within `run_list`, but in general it is clearer
//    to introduce `run_conditional` and `run_pipeline` functions that
//    are called by `run_list`. It’s up to you.
//
//    PHASE 2: Introduce a loop to run a list of commands, waiting for each
//       to finish before going on to the next.
//    PHASE 3: Change the loop to handle conditional chains.
//    PHASE 4: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PHASE 5: Change the loop to handle background conditional chains.
//       This may require adding another call to `fork()`!

void run_list(shell_parser sec) {

    // Commandline BNF **can** be empty
    auto cond = sec.first_conditional();

    // Run any conditionals
    while (cond) {
        run_conditional(cond);
        cond.next_conditional();
    }
}


int main(int argc, char* argv[]) {
    FILE* command_file = stdin;
    bool quiet = false;

    // Check for `-q` option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = true;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            return 1;
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) {
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr) {
            if (ferror(command_file) && errno == EINTR) {
                // ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                if (ferror(command_file)) {
                    perror("sh61");
                }
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            run_list(shell_parser{buf});
            bufpos = 0;
            needprompt = 1;
        }

        // Handle zombie processes and/or interrupt requests
        // Your code here!
    }

    return 0;
}
