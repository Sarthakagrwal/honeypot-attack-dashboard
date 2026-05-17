"""A simulated interactive shell for the SSH honeypot.

CRITICAL SAFETY PROPERTY: this module NEVER executes, evaluates, interprets or
spawns anything an attacker sends. Every "command" is resolved by a pure
dictionary lookup that returns a hard-coded string; unknown input yields a
canned ``command not found`` message. There is deliberately no import of
``subprocess``, ``os.system``, ``eval``, ``exec`` or any other execution
primitive in this file.

The shell merely makes the honeypot convincing enough that automated attackers
reveal their post-compromise playbook, which is then logged for study.
"""

from __future__ import annotations

from collections.abc import Callable

from . import events
from .config import Config

# --- Cosmetic terminal constants -------------------------------------------

PROMPT = "root@web-prod-01:~# "

MOTD = (
    "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)\r\n"
    "\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n"
    "\r\n"
    "  System information as of "
    "Mon May  6 09:14:22 UTC 2024\r\n"
    "\r\n"
    "  System load:  0.08              Processes:             128\r\n"
    "  Usage of /:   41.2% of 38.6GB   Users logged in:       0\r\n"
    "  Memory usage: 23%               IPv4 address for eth0: 10.0.0.7\r\n"
    "  Swap usage:   0%\r\n"
    "\r\n"
    "Last login: Mon May  6 08:51:07 2024 from 10.0.0.1\r\n"
)

# --- Canned command responses ----------------------------------------------
#
# A plain str maps to fixed output. A callable receives the raw argument
# string and returns output, used only for commands whose *shape* of reply
# depends on the argument (e.g. echoing a filename back) — still never running
# anything.

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
)

_CPUINFO = (
    "processor\t: 0\n"
    "vendor_id\t: GenuineIntel\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
    "cpu MHz\t\t: 2400.070\n"
    "cache size\t: 30720 KB\n"
    "processor\t: 1\n"
    "vendor_id\t: GenuineIntel\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
    "cpu MHz\t\t: 2400.070\n"
    "cache size\t: 30720 KB\n"
)

_PS = (
    "  PID TTY          TIME CMD\n"
    " 1842 pts/0    00:00:00 bash\n"
    " 1979 pts/0    00:00:00 ps\n"
)

_PS_AUX = (
    "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    "root         1  0.0  0.1 168140 11200 ?        Ss   May06   0:04 /sbin/init\n"
    "root       412  0.0  0.2  72308  6404 ?        Ss   May06   0:00 /usr/sbin/sshd -D\n"
    "www-data   980  0.0  0.4 214000 16800 ?        S    May06   0:01 /usr/sbin/apache2 -k start\n"
    "root      1842  0.0  0.1  10100  5200 pts/0    Ss   09:14   0:00 -bash\n"
)

_IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.0.0.7  netmask 255.255.255.0  broadcast 10.0.0.255\n"
    "        ether 06:7f:12:3a:9c:01  txqueuelen 1000  (Ethernet)\n"
    "        RX packets 184221  bytes 248113302 (248.1 MB)\n"
    "        TX packets 92140  bytes 13882011 (13.8 MB)\n"
    "\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
    "        loop  txqueuelen 1000  (Local Loopback)\n"
)

_IP_A = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
    "    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
    "    inet 10.0.0.7/24 brd 10.0.0.255 scope global eth0\n"
)

_LS = "backup.tar.gz  notes.txt  public_html  scripts\n"

_HELP = (
    "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"
    "These shell commands are defined internally.\n"
)


def _echo(arg: str) -> str:
    """Return ``echo``'s argument verbatim — pure string passthrough, no shell."""
    return arg + "\n" if arg else "\n"


def _network_fetch(arg: str) -> str:
    """Canned reply for wget/curl: it looks plausible but downloads nothing."""
    if not arg:
        return "wget: missing URL\n"
    return (
        "Resolving host... failed: Temporary failure in name resolution.\n"
        f"wget: unable to resolve host address for '{arg.split()[0]}'\n"
    )


# command -> str (static output) | Callable[[str], str] (arg-aware output)
_COMMANDS: dict[str, str | Callable[[str], str]] = {
    "ls": _LS,
    "ls -la": "total 28\n" + _LS.replace("  ", "\n").rstrip() + "\n",
    "ll": _LS,
    "pwd": "/root\n",
    "whoami": "root\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\n",
    "uname": "Linux\n",
    "uname -a": (
        "Linux web-prod-01 5.15.0-101-generic #111-Ubuntu SMP "
        "Tue Mar 5 20:16:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
    ),
    "uname -r": "5.15.0-101-generic\n",
    "hostname": "web-prod-01\n",
    "cat /etc/passwd": _PASSWD,
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied\n",
    "cat /proc/cpuinfo": _CPUINFO,
    "cat /etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"\n'
        'NAME="Ubuntu"\n'
        'VERSION_ID="22.04"\n'
    ),
    "ps": _PS,
    "ps aux": _PS_AUX,
    "ps -ef": _PS_AUX,
    "ifconfig": _IFCONFIG,
    "ip a": _IP_A,
    "ip addr": _IP_A,
    "free -m": (
        "               total        used        free      shared\n"
        "Mem:            3936         912        2210          12\n"
        "Swap:              0           0           0\n"
    ),
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/xvda1       39G   16G   23G  41% /\n"
    ),
    "w": " 09:14:55 up 5 days,  2:23,  1 user,  load average: 0.08, 0.03, 0.01\n",
    "uptime": " 09:14:55 up 5 days,  2:23,  1 user,  load average: 0.08, 0.03, 0.01\n",
    "history": "    1  ls\n    2  uname -a\n    3  whoami\n",
    "history -c": "",
    "crontab -l": "no crontab for root\n",
    "apt": "apt 2.4.10 (amd64)\nUsage: apt [options] command\n",
    "apt-get": "apt 2.4.10 (amd64)\nUsage: apt-get [options] command\n",
    "help": _HELP,
    "env": "SHELL=/bin/bash\nPWD=/root\nLOGNAME=root\nHOME=/root\nUSER=root\n",
    "date": "Mon May  6 09:14:55 UTC 2024\n",
    "echo": _echo,
    "wget": _network_fetch,
    "curl": _network_fetch,
    "lscpu": (
        "Architecture:            x86_64\n"
        "CPU(s):                  2\n"
        "Model name:              Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
    ),
}

_EXIT_WORDS = {"exit", "logout", "quit"}


def resolve_command(line: str) -> str:
    """Resolve a command line to canned output (a pure function, no execution).

    Resolution order: exact match on the whole line, then match on the first
    token (so ``cat /tmp/x`` and ``echo hi`` route correctly). Anything
    unmatched returns a realistic ``command not found`` message. This function
    is the heart of the safety guarantee — it only ever indexes a dict.
    """
    line = line.strip()
    if not line:
        return ""

    # 1. Exact whole-line match (covers multi-word canned entries like "ps aux").
    exact = _COMMANDS.get(line)
    if exact is not None:
        return exact if isinstance(exact, str) else exact("")

    # 2. First-token match, passing the remainder as the argument string.
    parts = line.split(maxsplit=1)
    cmd = parts[0]
    arg = parts[1] if len(parts) > 1 else ""
    handler = _COMMANDS.get(cmd)
    if handler is not None:
        return handler if isinstance(handler, str) else handler(arg)

    # 3. Unknown -> canned bash error. Input is never run.
    return f"bash: {cmd}: command not found\n"


def run_shell(channel: object, session_id: int, conn: object, config: Config) -> None:
    """Drive the interactive fake shell over an open paramiko channel.

    Reads bytes from ``channel``, performs minimal line editing (backspace,
    echo), and for each completed line logs the command via
    :func:`honeypot.events.log_command` then writes back canned output. The
    loop ends on ``exit``/``logout``, EOF, or when the per-session command cap
    is reached. ``channel`` is typed loosely so tests can pass a fake.
    """
    send = channel.send  # type: ignore[attr-defined]
    send(MOTD)
    send(PROMPT)

    buffer = ""
    command_count = 0

    while True:
        try:
            data = channel.recv(1024)  # type: ignore[attr-defined]
        except (TimeoutError, OSError, EOFError):
            break
        if not data:  # EOF / closed channel.
            break

        text = data.decode("utf-8", errors="replace")
        for ch in text:
            if ch in ("\r", "\n"):
                send("\r\n")
                line = buffer
                buffer = ""

                stripped = line.strip()
                if not stripped:
                    send(PROMPT)
                    continue

                # Cap the recorded command length defensively.
                recorded = stripped[: config.max_command_length]
                events.log_command(conn, session_id=session_id, command=recorded)  # type: ignore[arg-type]
                command_count += 1

                if stripped.split()[0] in _EXIT_WORDS:
                    send("logout\r\n")
                    return

                send(resolve_command(stripped))

                if command_count >= config.max_commands_per_session:
                    send("\r\nConnection closed.\r\n")
                    return

                send(PROMPT)

            elif ch in ("\x7f", "\x08"):  # DEL / Backspace.
                if buffer:
                    buffer = buffer[:-1]
                    send("\b \b")

            elif ch == "\x03":  # Ctrl-C — abandon the current line.
                send("^C\r\n")
                buffer = ""
                send(PROMPT)

            elif ch == "\x04":  # Ctrl-D — logout on an empty line.
                if not buffer:
                    send("logout\r\n")
                    return

            elif ch.isprintable():
                # Bound the line so a flood cannot grow memory without limit.
                if len(buffer) < config.max_command_length:
                    buffer += ch
                    send(ch)
