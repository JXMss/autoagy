// The seccomp-BPF program that autoagy loads into its own bubblewrap sandbox
// (`bwrap --seccomp FD`). `--unshare-net` already removes IP networking, but a
// sandboxed command can still reach services listening on Unix sockets in the
// filesystem, which the read-only root bind does not close. The program mirrors
// Codex's `install_network_seccomp_filter_on_current_thread`:
//
//   - `socket`/`socketpair` are limited to AF_UNIX;
//   - the calls that set up or use a connection are denied with EPERM;
//   - `ptrace`, `process_vm_*` and `io_uring_*` are denied unconditionally.
//
// EPERM (not a kill) is deliberate: a program that needs one of these gets an
// ordinary error it can report, instead of dying with SIGSYS.
//
// On x86-64 the filter also has to refuse the x32 ABI's syscall numbers, and
// that is not a detail: `seccomp_data.arch` is `AUDIT_ARCH_X86_64` for an x32
// call too — the ABI is marked by bit 30 of the *number* — so an arch guard
// alone lets `0x40000000 | SYS_socket` through to a table that does not name
// it, and the call is allowed. Measured on this host (kernel with
// CONFIG_X86_X32_ABI=y), inside a real bwrap with this filter: `socket(AF_INET)`
// returns EPERM as intended, `syscall(0x40000000 | 41, AF_INET, SOCK_STREAM, 0)`
// returns a descriptor, and the same holds for `connect` and `sendto`. Rejecting
// the bit is what libseccomp and Chromium do (Chromium tests it with a JSET).
// An x32 binary therefore cannot run in this sandbox at all, which is the
// intended answer: nothing here needs the ABI, and Codex's own filter is built
// the same way.

import fs from 'node:fs';
import path from 'node:path';

// Byte offsets into `struct seccomp_data`.
const OFFSET_NR = 0;
const OFFSET_ARCH = 4;
const OFFSET_ARG0 = 16;

const AUDIT_ARCH = { x64: 0xc000003e, arm64: 0xc00000b7 };
const AF_UNIX = 1;
// x86-64 x32 ABI: syscall numbers carry bit 30. `seccomp_data.arch` cannot tell
// the two ABIs apart, so the number is what has to be refused.
const X32_SYSCALL_BIT = 0x4000_0000;

const RET_KILL_PROCESS = 0x80000000;
const RET_ALLOW = 0x7fff0000;
const RET_ERRNO_EPERM = 0x00050000 | 1;

// BPF instruction classes (cBPF, as prctl(PR_SET_SECCOMP) expects them).
const LD_W_ABS = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JSET_K = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const RET_K = 0x06; // BPF_RET | BPF_K

const SYS = {
  x64: {
    ptrace: 101,
    accept4: 288,
    socket: 41,
    connect: 42,
    accept: 43,
    sendto: 44,
    sendmsg: 46,
    shutdown: 48,
    bind: 49,
    listen: 50,
    getsockname: 51,
    getpeername: 52,
    socketpair: 53,
    setsockopt: 54,
    getsockopt: 55,
    recvmmsg: 299,
    sendmmsg: 307,
    process_vm_readv: 310,
    process_vm_writev: 311,
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
  },
  arm64: {
    ptrace: 117,
    socket: 198,
    socketpair: 199,
    bind: 200,
    listen: 201,
    accept: 202,
    connect: 203,
    getsockname: 204,
    getpeername: 205,
    sendto: 206,
    sendmsg: 211,
    setsockopt: 208,
    getsockopt: 209,
    shutdown: 210,
    accept4: 242,
    recvmmsg: 243,
    sendmmsg: 269,
    process_vm_readv: 270,
    process_vm_writev: 271,
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
  },
};

// Denied whatever the arguments are.
//
// `sendmsg` belongs here and used to be missing. The reason it was left out —
// tools that manage child processes through a socketpair need it, cargo clippy
// being Codex's example — does not hold: `read`/`write` already work on a
// socketpair, which is what those tools use, and the call is not restricted to
// connected sockets. An unconnected `AF_UNIX`/`SOCK_DGRAM` socket can name its
// destination in `msg_name`, which is exactly the reach `--unshare-net` cannot
// close and this filter exists for. Measured inside a real bwrap with this
// filter: `sendto` to a host datagram socket returns EPERM while `sendmsg` with
// the same destination returns ENOENT — that is, it reached the kernel and
// would have been delivered (one-way: `bind` is denied, so the sandbox cannot
// name itself and gets no reply). The target that makes this matter is
// `/run/systemd/journal/socket`, where a datagram is a log entry the sandbox
// wrote.
//
// `recvfrom` and `recvmsg` stay allowed, for the reason Codex keeps `recvfrom`:
// receiving is not injection, and a tool that reads a socketpair may use them.
// The three socket *queries* (`getsockopt`, `getsockname`, `getpeername`) are
// left out because denying them breaks any program that writes to a
// non-blocking pipe — measured with node, whose libuv stream setup gives up on
// the fd and drops the output silently; that is how a test runner reports
// results, and it fails with no error at all. Nothing is lost by allowing them:
// `socket`/`socketpair` are limited to AF_UNIX and every call that sets up or
// uses a connection is still denied, so a query has nothing left to report on.
const DENIED = [
  'ptrace',
  'process_vm_readv',
  'process_vm_writev',
  'io_uring_setup',
  'io_uring_enter',
  'io_uring_register',
  'connect',
  'accept',
  'accept4',
  'bind',
  'listen',
  'shutdown',
  'sendto',
  'sendmsg',
  'sendmmsg',
  'recvmmsg',
  'setsockopt',
];

/** The kernel's audit arch token for this machine, or null when unsupported. */
export function seccompArch(arch = process.arch) {
  return AUDIT_ARCH[arch] ?? null;
}

/** False when this machine's architecture has no filter, so the sandbox must not be used. */
export function seccompSupported(arch = process.arch) {
  return seccompArch(arch) !== null && Boolean(SYS[arch]);
}

/**
 * Assembles a program written with labels; cBPF jumps carry the number of
 * instructions to skip, so they are patched once every label is known. A jump
 * target of `null` means the instruction right after the jump.
 */
function assemble(build) {
  const program = [];
  const labels = new Map();
  const jumps = [];
  const emit = (code, k) => program.push({ code, jt: 0, jf: 0, k });
  const jump = (code, k, jt, jf) => {
    jumps.push({ at: program.length, jt, jf });
    emit(code, k);
  };
  build({
    label: (name) => labels.set(name, program.length),
    load: (offset) => emit(LD_W_ABS, offset),
    jumpIfEqual: (k, jt, jf) => jump(JEQ_K, k, jt, jf),
    // Taken when the accumulator has *any* of the bits in `k` set.
    jumpIfBitSet: (k, jt, jf) => jump(JSET_K, k, jt, jf),
    ret: (value) => emit(RET_K, value),
  });
  for (const { at, jt, jf } of jumps) {
    const step = (target) => {
      if (target === null) return 0;
      if (!labels.has(target)) throw new Error(`seccomp: unknown label ${target}`);
      const offset = labels.get(target) - (at + 1);
      // jt/jf are single bytes: the whole program has to fit in 255 of them.
      if (offset < 0 || offset > 255) throw new Error(`seccomp: jump out of range at instruction ${at}`);
      return offset;
    };
    program[at].jt = step(jt);
    program[at].jf = step(jf);
  }
  return program;
}

/**
 * The compiled filter: an array of `struct sock_filter` (8 bytes each), which
 * is what `bwrap --seccomp` reads from its file descriptor.
 * @returns {Buffer}
 */
export function seccompProgram(arch = process.arch) {
  const auditArch = seccompArch(arch);
  const table = SYS[arch];
  if (auditArch === null || !table) throw new Error(`autoagy has no seccomp filter for ${arch}`);

  const program = assemble(({ label, load, jumpIfEqual, jumpIfBitSet, ret }) => {
    // 32-bit compatibility syscalls enter the filter with their own arch token,
    // so they are killed here rather than silently falling through to ALLOW.
    load(OFFSET_ARCH);
    jumpIfEqual(auditArch, 'arch-ok', 'arch-reject');
    label('arch-ok');
    load(OFFSET_NR);
    // ...except on x86-64, where the x32 ABI is not a separate arch token at
    // all: the number carries bit 30 instead, so it never equals any entry in
    // the table and would fall through to ALLOW. Refusing the bit is the whole
    // check; see the note at the top of this file for the measurement.
    if (arch === 'x64') jumpIfBitSet(X32_SYSCALL_BIT, 'reject', null);
    for (const name of DENIED) jumpIfEqual(table[name], 'reject', null);
    // socket()/socketpair() may only create AF_UNIX pairs.
    for (const name of ['socket', 'socketpair']) {
      jumpIfEqual(table[name], `check-${name}`, `${name}-ok`);
      label(`check-${name}`);
      load(OFFSET_ARG0);
      jumpIfEqual(AF_UNIX, `after-${name}`, 'reject');
      label(`after-${name}`);
      load(OFFSET_NR);
      label(`${name}-ok`);
    }
    ret(RET_ALLOW);
    label('reject');
    ret(RET_ERRNO_EPERM);
    label('arch-reject');
    ret(RET_KILL_PROCESS);
  });
  return toBuffer(program);
}

function toBuffer(program) {
  const buffer = Buffer.alloc(program.length * 8);
  program.forEach((ins, i) => {
    buffer.writeUInt16LE(ins.code, i * 8);
    buffer.writeUInt8(ins.jt, i * 8 + 2);
    buffer.writeUInt8(ins.jf, i * 8 + 3);
    buffer.writeUInt32LE(ins.k >>> 0, i * 8 + 4);
  });
  return buffer;
}

/** Where the filter is kept so `bwrap --seccomp` can read it from a file descriptor. */
export function seccompProgramFile(autoagyHome, arch = process.arch) {
  const file = path.join(autoagyHome, 'state', `seccomp-${arch}.bpf`);
  const want = seccompProgram(arch);
  try {
    if (fs.readFileSync(file).equals(want)) return file;
  } catch {
    // not written yet
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, want);
  return file;
}
