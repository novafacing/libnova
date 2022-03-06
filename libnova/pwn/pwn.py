"""
Pwntools wrapper and convenience things!
"""


from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union, cast

from pwnlib.elf.elf import ELF
from pwnlib.gdb import debug
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.tubes.tube import tube


class PWMode(str, Enum):
    """
    Enum for pwn modes.
    """

    LOCAL = "local"
    REMOTE = "remote"
    DEBUG = "debug"
    AUTO = "auto"


class PW:
    """
    LibNova pwntools wrapper.
    """

    __slots__ = (
        "binary",
        "elf",
        "libc",
        "libs",
        "addr",
        "port",
        "mode",
        "local_args",
        "remote_args",
        "gdbscript",
        "p",
        "r",
    )

    def __init__(
        self,
        binary: Optional[Union[Path, str]] = None,
        addr: Optional[str] = None,
        port: Optional[int] = None,
        mode: PWMode = PWMode.AUTO,
        remote_args: Dict[str, Any] = {},
        local_args: Dict[str, Any] = {},
        gdbscript: str = "",
    ) -> None:
        """
        Initialize the pwntools wrapper.

        :param binary: The path to the binary to use, either a Path or string.
        :param addr: The address of the remote host eg 'ctf.hackucf.org'
        :param port: The port of the remote host eg 1337
        :param mode: The mode to use, either 'local', 'remote', 'debug' or 'auto'
        :param remote_args: Arguments to pass to remote tubes. Accepted arguments are:
            fam:
                The string "any", "ipv4" or "ipv6" or an integer to pass to
                socket.getaddrinfo.
            typ:
                The string "tcp" or "udp" or an integer to pass to socket.getaddrinfo.
            timeout:
                A positive number, None or the string "default".
            ssl(bool):
                Wrap the socket with SSL
            ssl_context(ssl.SSLContext):
                Specify SSLContext used to wrap the socket.
            sni:
                Set 'server_hostname' in ssl_args based on the host parameter.
            sock(socket.socket):
                Socket to inherit, rather than connecting
            ssl_args(dict):
                Pass ssl.wrap_socket named arguments in a dictionary.
        :param local_args: Arguments to pass to local tubes. Accepted arguments are:
            shell(bool):
                Set to True to interpret argv as a string to pass to the shell for
                interpretation instead of as argv.
            executable(str):
                Path to the binary to execute. If None, uses argv[0]. Cannot be used
                with shell.
            cwd(str):
                Working directory. Uses the current working directory by default.
            env(dict):
                Environment variables. By default, inherits from Python's environment.
            stdin(int):
                File object or file descriptor number to use for stdin. By default,
                a pipe is used. A pty can be used instead by setting this to PTY. This
                will cause programs to behave in an interactive manner (e.g.., python
                will show a >>> prompt). If the application reads from /dev/tty
                directly, use a pty.
            stdout(int):
                File object or file descriptor number to use for stdout. By default, a
                pty is used so that any stdout buffering by libc routines is disabled.
                May also be PIPE to use a normal pipe.
            stderr(int):
                File object or file descriptor number to use for stderr. By default,
                STDOUT is used. May also be PIPE to use a separate pipe, although the
                pwnlib.tubes.tube.tube wrapper will not be able to read this data.
            close_fds(bool):
                Close all open file descriptors except stdin, stdout, stderr. By
                default, True is used.
            preexec_fn(callable):
                Callable to invoke immediately before calling execve.
            raw(bool):
                Set the created pty to raw mode (i.e. disable echo and control
                characters). True by default. If no pty is created, this has no effect.
            aslr(bool):
                If set to False, disable ASLR via personality (setarch -R) and setrlimit
                (ulimit -s unlimited).

                This disables ASLR for the target process. However, the setarch changes
                are lost if a setuid binary is executed.

                The default value is inherited from context.aslr. See setuid below for
                additional options and information.
            setuid(bool):
                Used to control setuid status of the target binary, and the
                corresponding actions taken.

                By default, this value is None, so no assumptions are made.

                If True, treat the target binary as setuid. This modifies the mechanisms
                used to disable ASLR on the process if aslr=False. This is useful for
                debugging locally, when the exploit is a setuid binary.

                If False, prevent setuid bits from taking effect on the target binary.
                This is only supported on Linux, with kernels v3.5 or greater.
            where(str):
                Where the process is running, used for logging purposes.
            display(list):
                List of arguments to display, instead of the main executable name.
            alarm(int):
                Set a SIGALRM alarm timeout on the process.

        :param gdbscript: The path to the gdbscript to use.
        """

        if isinstance(binary, Path):
            self.binary: Optional[Path] = binary
        elif isinstance(binary, str):
            self.binary = Path(binary)
        else:
            self.binary = None

        self.elf: Optional[ELF] = None  # type: ignore
        self.libc: Optional[ELF] = None  # type: ignore
        self.libs: Optional[Dict[str, ELF]] = None  # type: ignore

        if self.binary is not None and not self.binary.is_file():
            raise FileNotFoundError(f"{self.binary} is not a file")
        elif self.binary is not None:
            self.elf = ELF(str(self.binary.resolve()))
            self.libc = self.elf.libc
            self.libs = {}

            for lib in self.elf.libs:
                if (lname := Path(lib).name) != self.binary.name:
                    self.libs[lname] = ELF(lib)

        self.addr = addr
        self.port = port
        self.mode = mode
        self.local_args = local_args
        self.remote_args = remote_args
        self.gdbscript = gdbscript

        self.p, self.r = self.open_tubes()

        if self.p is None and self.r is None:
            raise Exception("Could not open any tubes.")
        elif self.p is not None and self.r is not None:
            raise Exception("Cannot open both local and remote tubes.")

    def open_tubes(self) -> Tuple[Optional[tube], Optional[tube]]:  # type: ignore
        """
        Open process and remote tubes based on the given mode.
        """
        p, r = None, None
        if self.mode == PWMode.AUTO:
            # Remote takes precedence
            if self.addr is not None and self.port is not None:
                r = remote(self.addr, self.port, **self.remote_args)
            elif self.binary is not None:
                p = process(str(self.binary.resolve()), **self.local_args)
        elif self.mode == PWMode.LOCAL:
            if self.binary is not None:
                p = process(str(self.binary.resolve()), **self.local_args)
        elif self.mode == PWMode.REMOTE:
            if self.addr is not None and self.port is not None:
                r = remote(self.addr, self.port, **self.remote_args)
        elif self.mode == PWMode.DEBUG:
            if self.binary is not None:
                p = debug(str(self.binary.resolve()), gdbscript=self.gdbscript)

        return p, r

    def __getattr__(self, name: str) -> Any:
        """
        Proxy all unknown attributes to the local tube.
        """
        if hasattr(self, name):
            return getattr(self, name)

        if self.p is not None:
            return getattr(self.p, name)
        elif self.r is not None:
            return getattr(self.r, name)

        raise AttributeError(
            f"{name} is not a valid attribute of this class or its tube!"
        )
