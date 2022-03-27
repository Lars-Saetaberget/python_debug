import ctypes
import enum
import os
import signal


class PtraceRequestType(enum.Enum):
    PEEKTEXT   = 1
    PEEKDATA   = 2
    POKETEXT   = 4
    POKEDATA   = 5
    CONT       = 7
    SINGLESTEP = 9
    GETREGS    = 12
    SETREGS    = 13
    ATTACH     = 16
    DETACH     = 17


class UserRegsStruct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class TraceSession:
    def __init__(self, pid: int):
        self.pid = pid
        self.ptrace = ctypes.CDLL('libc.so.6').ptrace

    def attach(self) -> bool:
        """
        Attempt to attach to the provided pid using ptrace
        :param pid: Process ID to attach to
        :return: True if successfully attached
        """
        self.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
        self.ptrace.restype = ctypes.c_uint64

        self.__ptrace_request(PtraceRequestType.ATTACH, self.pid)

        stat = os.waitpid(self.pid, 0)
        if os.WIFSTOPPED(stat[1]):
            return os.WSTOPSIG(stat[1]) == signal.SIGSTOP
        return False

    def read_data(self, address: int, size: int, word_size=8):
        """
        Read <size> bytes from the provided address
        :param address: Address to read from
        :param size: Number of bytes to read
        :param word_size:
        :return:
        """
        if size % word_size != 0:
            print("WARNING! Size is not a multiple of the word size, which you very likely don't want.")

        offset = 0
        data = {}

        while offset < size:
            data[hex(address+offset)] = self.__ptrace_request(PtraceRequestType.PEEKDATA, address + offset)
            offset += word_size

        return data

    def __ptrace_request(self, request: PtraceRequestType, offset=None, data=None):
        """
        Perform a single ptrace request
        :param request: The ptrace request type
        :param offset: The address offset
        :param data: The data buffer to sen
        """
        return self.ptrace(request.value, self.pid, offset, data)
