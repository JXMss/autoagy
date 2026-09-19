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

import fs from 'node:fs';
import path from 'node:path';

// Byte offsets into `struct seccomp_data`.
const OFFSET_NR = 0;
const OFFSET_ARCH = 4;
const OFFSET_ARG0 = 16;

const AUDIT_ARCH = { x64: 0xc000003e, arm64: 0xc00000b7 };
const AF_UNIX = 1;

const RET_KILL_PROCESS = 0x80000000;
const RET_ALLOW = 0x7fff0000;
const RET_ERRNO_EPERM = 0x00050000 | 1;

// BPF instruction classes (cBPF, as prctl(PR_SET_SECCOMP) expects them).
const LD_W_ABS = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const RET_K = 0x06; // BPF_RET | BPF_K

const SYS = {
  x64: {
    ptrace: 101,
    accept4: 288,
    socket: 41,
    connect: 42,
    accept: 43,
    sendto: 44,
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
// Codex also denies `recvfrom`, `sendmsg`, `getsockopt`, `getsockname` and
// `getpeername` here. The first two are left out because tools that manage
// child processes through a socketpair need them (cargo clippy is the example
// Codex names). The three socket queries are left out because denying them
// breaks any program that writes to a non-blocking pipe — measured with node,
// whose libuv stream setup gives up on the fd and drops the output silently;
// that is how a test runner reports results, and it fails with no error at all.
// Nothing is lost by allowing them: `socket`/`socketpair` are limited to
// AF_UNIX and every call that sets up or uses a connection is still denied, so
// a query has nothing left to report on.
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
  build({
    label: (name) => labels.set(name, program.length),
    load: (offset) => emit(LD_W_ABS, offset),
    jumpIfEqual: (k, jt, jf) => {
      jumps.push({ at: program.length, jt, jf });
      emit(JEQ_K, k);
    },
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

  const program = assemble(({ label, load, jumpIfEqual, ret }) => {
    // 32-bit compatibility syscalls enter the filter with their own arch token,
    // so they are killed here rather than silently falling through to ALLOW.
    load(OFFSET_ARCH);
    jumpIfEqual(auditArch, 'arch-ok', 'arch-reject');
    label('arch-ok');
    load(OFFSET_NR);
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
