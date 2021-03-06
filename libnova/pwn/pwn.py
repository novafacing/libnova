"""
Pwntools wrapper and convenience things!
"""


from enum import Enum
from logging import getLogger
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from pwnlib.elf.corefile import Corefile
from pwnlib.elf.elf import ELF
from pwnlib.gdb import debug
from pwnlib.timeout import Timeout
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import remote
from pwnlib.tubes.tube import tube
from pwnlib.util.cyclic import cyclic

from libnova.util.replayable import MethodReplayable

l = getLogger(__file__)


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
        self.libs: Dict[str, ELF] = {}  # type: ignore

        if self.binary is not None and not self.binary.is_file():
            raise FileNotFoundError(f"{self.binary} is not a file")
        elif self.binary is not None:
            self.elf = ELF(str(self.binary.resolve()), checksec=False)
            self.libs = {}

            for lib in self.elf.libs:
                if (lname := Path(lib).name) != self.binary.name:
                    self.libs[lname] = ELF(lib, checksec=False)
                    if "libc" in lname.lower():
                        self.libc = self.libs[lname]

        self.addr = addr
        self.port = port
        self.mode = mode
        self.local_args = local_args
        self.remote_args = remote_args
        self.gdbscript = gdbscript
        self.replay_sends: List[MethodReplayable] = []

        self.p, self.r = self.open_tubes()

        if self.p is None and self.r is None:
            raise Exception("Could not open any tubes.")
        elif self.p is not None and self.r is not None:
            raise Exception("Cannot open both local and remote tubes.")

        self.checksec()

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

    # Tube proxy method

    def __getattr__(self, name: str) -> Any:
        """
        Proxy all unknown attributes to the local tube.

        :param name: The name of the attribute to proxy.
        """
        if self.p is not None:
            return getattr(self.p, name)
        elif self.r is not None:
            return getattr(self.r, name)

        raise AttributeError(
            f"{name} is not a valid attribute of this class or its tube!"
        )

    # Convenience methods

    def checksec(self) -> None:
        """
        Check the security of the binary.
        """
        for lib, elf in self.libs.items():
            if (self.elf is not None and elf.path != self.elf.path) or self.elf is None:
                l.info(f"Checksec info for library: {lib}")
                for ln in elf.checksec().splitlines():
                    l.info(ln)
        if self.elf is not None:
            l.info(f"Checksec info for main object: {Path(self.elf.path).name}")
            for ln in self.elf.checksec().splitlines():
                l.info(ln)

    # Printer proxy methods

    def precvall(self) -> bytes:
        """
        Receive all data from the remote tube and print it.

        :return: All data received from the remote tube.
        """
        b: bytes = self.recvall()
        print(b)
        return b

    def precvline(self) -> bytes:
        """
        Receive a line from the remote tube and print it.

        :return: A line received from the remote tube.
        """
        b: bytes = self.recvline()
        print(b)
        return b

    def precv(self, numb: int) -> bytes:
        """
        Receive n bytes from the remote tube and print it.

        :param numb: The number of bytes to receive.
        :return: The n bytes received from the remote tube.
        """
        b: bytes = self.recvn(numb)
        print(b)
        return b

    def precvuntil(self, delim: str, drop: bool = True) -> bytes:
        """
        Receive data from the remote tube until the delimiter is found.

        :param delim: The delimiter to use.
        :param drop: Whether to drop the delimiter.
        :return: The data received from the remote tube.
        """
        b: bytes = self.recvuntil(delim, drop=drop)
        print(b)
        return b

    # Short name aliases

    def sla(self, delim: bytes, data: bytes) -> None:
        """
        Send data to the remote tube and receive until the delimiter is found.

        :param delim: The delimiter to use.
        :param data: The data to send.
        :param timeout: The timeout to use.
        """
        self.sendlineafter(delim, data)
        self.replay_sends.append(
            MethodReplayable(
                "sendlineafter",
                (
                    delim,
                    data,
                ),
            )
        )

    def sl(self, data: bytes) -> None:
        """
        Send data to the remote tube.

        :param data: The data to send.
        """
        self.sendline(data)
        self.replay_sends.append(MethodReplayable("sendline", (data,)))

    def rcv(self, numb: int) -> bytes:
        """
        Receive n bytes from the remote tube.

        :param numb: The number of bytes to receive.
        :return: The n bytes received from the remote tube.
        """
        b: bytes = self.recv(numb)
        return b

    def rcvu(self, delim: str, drop: bool = True) -> bytes:
        """
        Receive data from the remote tube until the delimiter is found.

        :param delim: The delimiter to use.
        :param drop: Whether to drop the delimiter.
        :return: The data received from the remote tube.
        """
        b: bytes = self.recvuntil(delim, drop=drop)
        return b

    def rcva(self) -> bytes:
        """
        Receive all data from the remote tube.

        :return: All data received from the remote tube.
        """
        b: bytes = self.recvall()
        return b

    def crash(self, size: int) -> Optional[Corefile]:
        """
        Crash the process with a large amount of data, try to get a core, and
        obtain offset in the input that caused the crash to construct
        exploits.

        :param size: The size of the data to crash with.
        """
        crashproc = process(str(self.binary.resolve()), **self.local_args)
        for send in self.replay_sends:
            send.replay(crashproc)

        crashproc.sendline(cyclic(size))
        crashproc.recv(timeout=1)
        try:
            core = crashproc.corefile
            crashproc.close()
        except BrokenPipeError:
            ...

        if core is None:
            l.error(f"Failed to get core for crash of size {size}")

        return core
