#define GRADING_MODE                    // Enable grading server compatibility

#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <set>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>

#ifndef GRADING_MODE
#include <filesystem>
#endif

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

#ifdef GRADING_MODE
#define MORE_ERROR_MESSAGES false       // `false` for test-passing purposes
#else
#define MORE_ERROR_MESSAGES true
#endif


// SIGINT_HANDLER(sig)
//    Handler for `SIGINT`

volatile sig_atomic_t interrupted = 0;
void SIGINT_HANDLER(int sig) {
    interrupted = sig;
}


// type_redirections
//    Constant set of the possible types of redirections

const std::set<int> type_redirections = {
    TYPE_LHOINKY,
    TYPE_RHOINKY, TYPE_RRHOINKY,
    TYPE_2RHOINKY, TYPE_2RRHOINKY,
    TYPE_ARHOINKY, TYPE_ARRHOINKY
};


// Internal exit statuses: 0-255 are reserved for system-defined statuses
#define ERR_NOTEXIT     -1
#define ERR_SYNTAX      -2
#define ERR_UNKNOWN     -3
#define ERR_FORK        -4
#define ERR_PIPE        -5
#define ERR_PARSE       -6
#define ERR_SETPGID     -7
// Some `last_exit` assignments are unused but may make future features easier
int last_exit;                          //Exit status of the last pipeline


// is_foreground
//    Global boolean marking foreground (main shell) or background (subshell)

bool is_foreground = true;


// subshells
//    Global vector of subshell PIDs

std::vector<pid_t> subshells;


// struct command
//    Data structure describing a command. Add your own stuff.

struct redirection {
    int dest;                   // Replacing either stdin, stdout, or stderr
    std::string file;           // Filename
    bool append;                // Append/truncate the file
};
struct command {
    std::vector<std::string> args;
    std::vector<redirection> redirections;

    pid_t pid = -1;             // process ID running this command, -1 if none
    pid_t pgid = -1;            // group ID of this pipeline, -1 if not set yet

    int infd = STDIN_FILENO;    // FD to map `STDIN_FILENO` onto
    int outpipe[2] = {-1, STDOUT_FILENO};
                                // outbound pipe, `outpipe[0]` is read end
                                //                `outpipe[1]` is write end

    command();
    ~command();

    void run();

    void pipe();                // Helpers to `run`
    void redirect();
    void cd();
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


#ifndef GRADING_MODE
// fd_count
//    Returns number of open FDs in current process.
//    Only used for assertions and debugging.
//    See citation: `fdcount`

long fd_count() {
  return std::distance(std::filesystem::directory_iterator("/proc/self/fd"),
                       std::filesystem::directory_iterator{});
}
#endif


// fd_remap(src, dst)
//    Remap `dst` to `src`s file, respecting fd hygiene.
//    Only called by child processes preparing for command execution.

void fd_remap(int src, int dst) {
    if (dup2(src, dst) == -1) {
        std::cerr << "sh61: failed dup2\n";
        _exit(EXIT_FAILURE);
    }
    if (close(src) == -1) {
        std::cerr << "sh61: failed close\n";
        _exit(EXIT_FAILURE);
    }
}


// is_fd_open(fd)
//    Returns `true` if the file associated with `fd` is still open

bool is_fd_open(int fd) {
    while (fcntl(fd, F_GETFD) == -1) {
        if (errno == EBADF) return false;
    }
    return true;
}


// reap
//    Reap zombie processes (free terminated subshells' process entries)

void reap() {
    for (auto it = subshells.begin(); it != subshells.end(); ++it) {
        if (waitpid(*it, nullptr, WNOHANG) == *it) subshells.erase(it--);
    }
}


// COMMAND EXECUTION

// command::pipe()
//    Set up pipes (if any) for this command

void command::pipe() {
    // Set child's PGID
    int pgid_r;
    if (this->pgid == -1) pgid_r = setpgrp();
    else pgid_r = setpgid(0, this->pgid);
    if (pgid_r == -1) {
        std::cerr << "sh61: failed setpgid\n";
        _exit(EXIT_FAILURE);
    }

    // Set up pipes if applicable
    if (this->infd != STDIN_FILENO) fd_remap(this->infd, STDIN_FILENO);
    if (this->outpipe[1] != STDOUT_FILENO) {
        assert(this->outpipe[0] != -1);
        close(this->outpipe[0]);
        fd_remap(this->outpipe[1], STDOUT_FILENO);
    } else assert(this->outpipe[0] == -1);

    // Confirm pipeline is still active (handles `SIGINT` race condition)
    if (!is_fd_open(STDIN_FILENO) || !is_fd_open(STDOUT_FILENO)) {
        _exit(130);         // exit status for `SIGINT`
    }
}


// command::redirect()
//    Set up redirections (if any) for this command

void command::redirect() {
    // Set up redirections if applicable (redirections will shadow pipes)
    for (auto re = this->redirections.begin();
                re != this->redirections.end();
                ++re) {

        assert(re->dest == 0 || re->dest == 1 || re->dest == 2);
        
        int redir;

        // Input redirection setup
        if (re->dest == STDIN_FILENO) {
            redir = openat(AT_FDCWD, re->file.c_str(), O_RDONLY);

        // Output/error redirection setup
        } else {
            // Set mode for open
            int mode = S_IRUSR | S_IWUSR
                        | S_IRGRP | S_IWGRP
                        | S_IROTH | S_IWOTH;       // `mode == 00666`
            
            // Set flags for open
            int flags = O_WRONLY | O_CREAT;
            if (re->append) flags |= O_APPEND;
            else flags |= O_TRUNC;

            // Open redirection file
            redir = openat(AT_FDCWD, re->file.c_str(), flags, mode);
        }

        // Perform redirection
        if (redir == -1) {
            std::cerr << "sh61: "
                        << re->file.c_str()
                        << ": No such file or directory\n";
            _exit(EXIT_FAILURE);
        }
        fd_remap(redir, re->dest);
    }
}


// command:cd()
//    Run special the command "cd"

void command::cd() {

    // Setup
    this->pid = getpid();
    std::string target_directory;
    int temp_stdin = dup(STDIN_FILENO);
    int temp_stdout = dup(STDOUT_FILENO);
    int temp_stderr = dup(STDERR_FILENO);
    this->redirect();

    // Command is just "cd"
    if (this->args.size() == 1) {
        target_directory = "/";

    // Command is "cd `this->args[1]`"
    } else if (this->args.size() == 2) {
        target_directory = this->args[1];

    // Too many args
    } else {
        std::cerr << "sh61: cd: too many arguments\n";
        last_exit = ERR_SYNTAX;

        // Cleanup
        fd_remap(temp_stdin, STDIN_FILENO);
        fd_remap(temp_stdout, STDOUT_FILENO);
        fd_remap(temp_stderr, STDERR_FILENO);

        return;
    }

    // Attempt cd
    int chdir_r = chdir(target_directory.c_str());
    if (chdir_r == 0) last_exit = EXIT_SUCCESS;
    else {
        last_exit = EXIT_FAILURE;
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

    // Cleanup
    fd_remap(temp_stdin, STDIN_FILENO);
    fd_remap(temp_stdout, STDOUT_FILENO);
    fd_remap(temp_stderr, STDERR_FILENO);
}


// command::run()
//    Run the command represented by `this`.
//
//    If returning, sets `this->pid` to:
//      child's PID for normal commands
//      current PID for "cd" commands
//
//    Sets global `last_exit` to:
//      `EXIT_SUCCESS` or `EXIT_FAILURE` for "cd" commands
//      `ERR_*` as defined above for parent errors
//
//
//    NOTES:
//      Creates a single child process running the command in `this`, and
//      sets `this->pid` to the pid of the child process.
//
//      If a child process cannot be created, this function should call
//      `_exit(fail)` (where `0 < fail <= 255`) to exit the containing
//      shell or subshell. If this function returns to its caller,
//      `this->pid > 0` must always hold.
//
//      `last_exit` should only be set in the parent process.
//
//      Note that this function must return to its caller *only* in the parent
//      process. The code that runs in the child process must `execvp` and/or
//      `_exit`.
//
//      PHASE 1: Fork a child process and run the command using `execvp`.
//         This will require creating a vector of `char*` arguments using
//         `this->args[N].c_str()`. Note that the last element of the vector
//         must be a `nullptr`.
//      PHASE 4: Set up a pipeline if appropriate. This may require creating a
//         new pipe (`pipe` system call), and/or replacing the child process's
//         standard input/output with parts of the pipe (`dup2` and `close`).
//         Draw pictures!
//      PHASE 7: Handle redirections.

void command::run() {

    // Command should be freshly built
    assert(this->pid == -1);
    // Command BNF is never empty
    assert(this->args.size() > 0);

    // Handle cd commands
    if (this->args.front() == "cd") return this->cd();

    // Fork
    pid_t fork_r = fork();

    // Child
    if (fork_r == 0) {

        // Redirections shadow pipes: pipe then redirect
        this->pipe();
        this->redirect();

        // Build args vector (`strdup` will call `malloc`)
        std::vector<char*> cstring_args;
        for (auto elt : this->args) cstring_args.push_back(strdup(elt.c_str()));
        cstring_args.push_back(nullptr);

        // Attempt execution
        int exec_r = execvp(cstring_args[0], cstring_args.data());

        // Failed `execvp`
        assert(exec_r == -1);
        std::cerr << cstring_args[0] << ": command not found\n";
        for (auto cstring : cstring_args) free(cstring);    // free `strdup`s
        _exit(127);                     // Command not found
    
    // Parent
    } else if (fork_r != -1) {
        this->pid = fork_r;
        if (this->pgid == -1) this->pgid = this->pid;
        if (setpgid(this->pid, this->pgid) == -1) {
            std::cerr << "sh61: failed setpgid\n";
            last_exit = ERR_SETPGID;
            abort();
        }


    // Fork error
    } else {
        std::cerr << "sh61: failed fork";
        last_exit = ERR_FORK;
        abort();
    }
}


// run_pipeline(ppln)
//    Run pipeline in parser object `ppln`.
//
//    Sets global `last_exit` to:
//      exit status of the last command in the pipeline (except for "cd"s)
//      `ERR_*` as defined above for shell errors
//
//
//    NOTES:
//      PHASE 4: Change the loop to handle pipelines. Start all processes in
//         the pipeline in parallel. The status of a pipeline is the status of
//         its LAST command.

void run_pipeline(shell_parser ppln) {

    // Pipeline BNF is never empty
    auto comm = ppln.first_command();
    assert(comm);

    // Locals
    int command_r;
    pid_t pid = getpid();
    pid_t pgid = -1;
    std::vector<pid_t> children;
    int next_infd = -1;
    #ifndef GRADING_MODE
    int initial_fds = fd_count();
    #endif

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
            if (type_redirections.find(type) != type_redirections.end()) {

                // Get redirection filename
                tok.next();
                if (!tok || tok.type() != TYPE_NORMAL) {
                    std::cerr << "sh61: syntax error near unexpected token `"
                              << tok.str()
                              << "`\n";
                    delete c;
                    last_exit = ERR_SYNTAX;
                    return;
                }

                // Redirection locals
                int append = -1;
                int dest = -1;

                // Append
                if (type == TYPE_RRHOINKY
                        || type == TYPE_2RRHOINKY
                        || type == TYPE_ARRHOINKY) {
                    append = 1;

                // Truncate
                } else if (type == TYPE_LHOINKY
                               || type == TYPE_RHOINKY
                               || type == TYPE_2RHOINKY
                               || type == TYPE_ARHOINKY) {
                    append = 0;
                }
                assert(append == 0 || append == 1);


                // Redirect stdin
                if (type == TYPE_LHOINKY) {
                    dest = 0;

                // Redirect stdout
                } else if (type == TYPE_RHOINKY || type == TYPE_RRHOINKY) {
                    dest = 1;
                
                // Redirect stderr
                } else if (type == TYPE_2RHOINKY || type == TYPE_2RRHOINKY) {
                    dest = 2;
                
                // Redirect both stdout and stderr
                } else if (type == TYPE_ARHOINKY || type == TYPE_ARRHOINKY) {
                    dest = 3;   // Means `dest` is both `1` and `2`
                }
                assert(dest != -1);


                // Mark redirection(s)
                redirection redir = {.dest = dest,
                                     .file = tok.str(),
                                     .append = (bool) append};
                if (dest == 3) {
                    redir.dest = 2;
                    c->redirections.push_back(redir);
                    redir.dest = 1;
                    c->redirections.push_back(redir);
                } else {
                    c->redirections.push_back(redir);
                }

            // Add any args
            } else if (type == TYPE_NORMAL) {
                c->args.push_back(tok.str());
            
            // Parser error
            } else {
                std::cerr << "sh61: parser error: `"
                          << tok.str()
                          << "` parsed in command\n";
                delete c;
                last_exit = ERR_PARSE;
                abort();
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
                last_exit = ERR_PIPE;
                return;
            }
            c->outpipe[0] = next_infd = pfds[0];
            c->outpipe[1] = pfds[1];
        }

        // Set command to run in pipeline's program group
        if (pgid != -1) c->pgid = pgid;

        // Attempt to run command
        c->run();
        assert(c->pid != -1);

        // Clean pipes
        if (c->infd != STDIN_FILENO) close(c->infd);
        if (c->outpipe[1] != STDOUT_FILENO) close(c->outpipe[1]);
        else assert(c->outpipe[0] == -1);

        // Add child or cd execution to vector
        children.push_back(c->pid);

        // Set pipeline's PGID
        if (pgid == -1) {
            pgid = c->pgid;
            if (is_foreground) claim_foreground(pgid);
        }

        // Iterate
        delete c;
        comm.next_command();
    }

    #ifndef GRADING_MODE
    // Check pipe hygiene
    int current_fds = fd_count();
    assert(initial_fds == current_fds);
    #endif

    // Wait for all commands in pipeline to exit
    for (auto child : children) {
        if (child != pid) waitpid(child, &command_r, WAIT_MYPGRP);
        if (WIFSIGNALED(command_r) && WTERMSIG(command_r) == SIGINT) {
            interrupted = SIGINT;
        }
    }

    claim_foreground(0);

    // Return based on the exit status of the **last** command in the pipeline
    // `children.back() == pid` means last command was "cd", `last_exit` is set
    if (children.back() != pid) {
        last_exit = WIFEXITED(command_r) ? WEXITSTATUS(command_r) : ERR_NOTEXIT;
    }
}


// run_conditional(cond)
//    Run conditional in parser object `cond`.
//    Only sets global `last_exit` on shell error (`ERR_*` as defined above).
//
//    NOTES:
//      PHASE 3: Change the loop to handle conditional chains.

void run_conditional(shell_parser cond) {

    // Conditional BNF is never empty
    auto ppln = cond.first_pipeline();
    assert(ppln);

    // Always run the first pipeline
    run_pipeline(ppln);
    bool cond_r = last_exit == 0;
    int op = ppln.op();
    ppln.next_pipeline();

    // Run post-conditional pipelines
    while (ppln) {

        // Parser error
        if (op && op != TYPE_AND && op != TYPE_OR) {
            std::cerr << "sh61: parser error: `"
                      << ppln.op_name()
                      << "` parsed as conditional operator\n";
            last_exit = ERR_PARSE;
            abort();
        }

        // If `true && next`, evaluate `next`
        if (op == TYPE_AND && cond_r) {
            run_pipeline(ppln);
            cond_r &= last_exit == 0;

        // If `false || next`, evaluate `next`
        } else if (op == TYPE_OR && !cond_r) {
            run_pipeline(ppln);
            cond_r |= last_exit == 0;
        }
        
        // Iterate
        op = ppln.op();
        ppln.next_pipeline();
    }

    // Update `last_exit`
    last_exit = cond_r;
}


// run_commandline(cmdl)
//    Run commandline in parser object `cmdl`.
//    Only sets global `last_exit` on shell error (`ERR_*` as defined above).
//
//    NOTES:
//      PHASE 1: Use `waitpid` to wait for the command started by `c->run()`
//          to finish.
//
//      The remaining phases may require that you introduce helper functions
//      (e.g., to process a pipeline), write code in `command::run`, and/or
//      change `struct command`.
//
//      It is possible, and not too ugly, to handle commandlines, conditionals,
//      *and* pipelines entirely within `run_commandline`, but in general it is
//      clearer to introduce `run_conditional` and `run_pipeline` functions that
//      are called by `run_commandline`. It’s up to you.
//
//      PHASE 2: Introduce a loop to run a sequence of conditionals, waiting
//         for each to finish before going on to the next.
//      PHASE 5: Change the loop to handle background conditional chains.
//         This may require adding another call to `fork()`!

void run_commandline(shell_parser cmdl) {

    // Commandline BNF **can** be empty
    auto cond = cmdl.first_conditional();

    // Run any conditionals
    while (cond && !interrupted) {

        // Background processes for `&` operators
        if (cond.op() == TYPE_BACKGROUND) {
            pid_t fork_r = fork();

            // Subshell
            if (fork_r == 0) {
                is_foreground = false;
                run_conditional(cond);
                _exit(last_exit != 0);

            // Main shell
            } else if (fork_r != -1) {
                subshells.push_back(fork_r);

            // Fork error
            } else {
                std::cerr << "sh61: failed fork";
                last_exit = ERR_FORK;
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
    set_signal_handler(SIGINT, SIGINT_HANDLER);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) {

        // Handle `SIGINT`
        if (interrupted == SIGINT) {
            printf("\n");
            needprompt = true;
            interrupted = 0;
            bufpos = 0;
            continue;
        };

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
            reap();
            run_commandline(shell_parser{buf});
            bufpos = 0;
            needprompt = 1;
            reap();
        }
    }

    reap();
    return 0;
}
