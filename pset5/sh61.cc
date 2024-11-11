#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>
#include <filesystem>

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

#define MORE_ERROR_MESSAGES false       // `false` for test-passing purposes

#define L_HOINKY 0
#define R_HOINKY 1
#define R2_HOINKY 2


// last_exit
//    Exit status of the last commandline execution

int last_exit;


// subshells
//    Global vector of subshell PIDs

std::vector<pid_t> subshells;


// struct command
//    Data structure describing a command. Add your own stuff.

struct redirection {
    int rtype;                  // type of redirection operator as defined above
    std::string file;           // filename
};
struct command {
    std::vector<std::string> args;
    std::vector<redirection> redirections;
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


// fd_remap(src, dst)
//    Remap `dst` to `src`s file, respecting fd hygiene.

void fd_remap(int src, int dst) {
    dup2(src, dst);
    close(src);
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

    // Handle cd commands
    if (this->args.front() == "cd") {

        // Setup
        this->pid = getpid();
        std::string target_directory;

        // Command is just "cd"
        if (this->args.size() == 1) {
            target_directory = "/";

        // Command is "cd `this->args[1]`"
        } else if (this->args.size() == 2) {
            target_directory = this->args[1];

        // Too many args
        } else {
            std::cerr << "sh61: cd: too many arguments\n";
            last_exit = 1;
            return;
        }

        // Attempt cd
        int chdir_r = chdir(target_directory.c_str());
        if (chdir_r == 0) last_exit = 0;
        else {
            last_exit = 1;
            // Give more error messaging if enabled
            if (MORE_ERROR_MESSAGES) {
                if (errno == ENOTDIR) {
                    std::cerr << "sh61: cd: "
                              << target_directory
                              << ": Not a directory\n";
                } else {
                    std::cerr << "sh61: cd: "
                              << target_directory
                              << ": No such file or directory\n";
                }
            }
        }
        return;
    }

    // Fork
    pid_t fork_r = fork();

    // Child
    if (fork_r == 0) {

        // Build args vector
        std::vector<char*> cstring_args;
        for (auto elt : this->args) cstring_args.push_back(strdup(elt.c_str()));
        cstring_args.push_back(nullptr);

        // Set up pipes if applicable
        if (this->infd != STDIN_FILENO) fd_remap(this->infd, STDIN_FILENO);
        if (this->outpipe[1] != STDOUT_FILENO) {
            assert(this->outpipe[0] != -1);
            close(this->outpipe[0]);
            fd_remap(this->outpipe[1], STDOUT_FILENO);
        } else assert(this->outpipe[0] == -1);

        // Set up redirections if applicable (redirections will shadow pipes)
        for (auto re : redirections) {
            assert(re.rtype == L_HOINKY
                       || re.rtype == R_HOINKY
                       || re.rtype == R2_HOINKY);
            
            int direction, redirection;

            // Input redirection setup
            if (re.rtype == L_HOINKY) {
                direction = STDIN_FILENO;
                redirection = openat(AT_FDCWD, re.file.c_str(), O_RDONLY);

            // Output/error redirection setup
            } else {
                if (re.rtype == R_HOINKY) direction = STDOUT_FILENO;
                else if (re.rtype == R2_HOINKY) direction = STDERR_FILENO;
                else {
                    std::cerr << "sh61: parser error: unknown redirection\n";
                    _exit(EXIT_FAILURE);
                }
                int mode = S_IRUSR | S_IWUSR
                         | S_IRGRP | S_IWGRP
                         | S_IROTH | S_IWOTH;       // `mode == 00666`
                redirection = openat(AT_FDCWD,
                                     re.file.c_str(),
                                     O_WRONLY | O_CREAT | O_TRUNC,
                                     mode);
            }

            // Perform redirection
            if (redirection == -1) {
                std::cerr << "sh61: "
                          << re.file.c_str()
                          << ": No such file or directory\n";
                _exit(EXIT_FAILURE);
            }
            fd_remap(redirection, direction);
        }

        // Attempt execution
        int exec_r = execvp(cstring_args[0], cstring_args.data());
        assert(exec_r == -1);
        std::cerr << cstring_args[0] << ": command not found\n";
        _exit(EXIT_FAILURE);
    
    // Parent
    } else if (fork_r != -1) {
        this->pid = fork_r;

    // Fork error
    } else {
        std::cerr << "sh61: failed fork";
        abort();
    }
}


// run_pipeline(pipeline)
//    Run the command *pipeline* contained in `section`.
//    Returns:
//      Success:  exit status of last command in pipeline
//      Fail:     `-1` on missing exit of last command in pipeline
//                `-2` on failed pipe creation
//                `-3` on syntax error

int run_pipeline(shell_parser ppln) {

    // Pipeline BNF is never empty
    auto comm = ppln.first_command();
    assert(comm);

    // Locals
    int command_r;
    pid_t pid = getpid();
    std::vector<pid_t> children;
    int next_infd = -1;
    int initial_fds = fd_count();

    // Run all commands in the pipeline
    while (comm) {

        // Command BNF is never empty
        auto tok = comm.first_token();
        assert(tok);

        // Build next command
        command* c = new command;
        while (tok) {
            int type = tok.type();

            // Add any redirections
            if (type == TYPE_REDIRECT_OP) {

                // Determine redirection type
                int rtype;
                if (tok.str() == "<") rtype = L_HOINKY;
                else if (tok.str() == ">") rtype = R_HOINKY;
                else if (tok.str() == "2>") rtype = R2_HOINKY;
                else {
                    std::cerr << "sh61: parser error: `"
                              << tok.str()
                              << "` parsed as `TYPE_REDIRECT_OP`\n";
                    delete c;
                    _exit(EXIT_FAILURE);
                }

                // Get redirection filename
                tok.next();
                if (!tok || tok.type() != TYPE_NORMAL) {
                    std::cerr << "sh61: syntax error near unexpected token `"
                              << tok.str()
                              << "`\n";
                    delete c;
                    return -3;
                }
                c->redirections.push_back({.rtype = rtype, .file = tok.str()});

            // Add any args
            } else if (type == TYPE_NORMAL) {
                c->args.push_back(tok.str());
            
            // Parser error
            } else {
                std::cerr << "sh61: parser error: `"
                          << tok.str()
                          << "` found in command\n";
                delete c;
                _exit(EXIT_FAILURE);
            }
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
            if (pipe_r == -1) {
                delete c;
                return -2;
            }
            c->outpipe[0] = next_infd = pfds[0];
            c->outpipe[1] = pfds[1];
        }

        // Attempt to run command
        c->run();
        assert(c->pid != -1);

        // Clean pipes
        if (c->infd != STDIN_FILENO) close(c->infd);
        if (c->outpipe[1] != STDOUT_FILENO) close(c->outpipe[1]);
        else assert(c->outpipe[0] == -1);

        // Add child or cd execution to vector
        children.push_back(c->pid);
        
        // Free command
        delete c;

        // Iterate
        comm.next_command();
    }

    // Check pipe hygiene
    int current_fds = fd_count();
    assert(initial_fds == current_fds);

    // Wait for all commands in pipeline to exit
    for (auto child : children) {
        if (child != pid) waitpid(child, &command_r, WAIT_MYPGRP);
    }

    // Return based on the exit status of the **last** command in the pipeline
    // Also update `last_exit` as needed
    if (children.back() == pid) return last_exit;
    else return last_exit = WIFEXITED(command_r) ? WEXITSTATUS(command_r) : -1;
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
        if (op == TYPE_AND && cond_r) {
            cond_r &= run_pipeline(ppln) == 0;

        // If `false || next`, evaluate `next`
        } else if (op == TYPE_OR && !cond_r) {
            cond_r |= run_pipeline(ppln) == 0;
        }
        
        // Iterate
        op = ppln.op();
        ppln.next_pipeline();
    }

    // Update `last_exit`
    last_exit = cond_r;
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

        // Background processes for `&` operators
        if (cond.op() == TYPE_BACKGROUND) {
            pid_t fork_r = fork();

            // Subshell
            if (fork_r == 0) {
                run_conditional(cond);
                _exit(EXIT_SUCCESS);

            // Main shell
            } else if (fork_r != -1) {
                subshells.push_back(fork_r);

            // Fork error
            } else {
                std::cerr << "sh61: failed fork";
                abort();
            }

        // Regular processes for singletons and `;` operators
        } else {
            run_conditional(cond);
        }

        // Iterate
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
        // Reap zombie processes (free terminated subshells' process entries)
        for (auto subshell : subshells) waitpid(subshell, nullptr, WNOHANG);
    }

    return 0;
}
