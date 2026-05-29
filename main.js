import { DataSec, RingBuf } from "yeet:bpf";
import bpf from "./ifacesniff.bpf.o";

/* ifacesniff — hex-dump every packet crossing one or more network
 * interfaces. The BPF side copies the raw frame (L2 header included)
 * into a ringbuf, bounded by a runtime snaplen; userspace decodes a
 * tcpdump-style summary line and a colored hex dump of the bytes. */

const DATA_SEC = "ifacesni.data"; /* libbpf truncates obj_name to 8 chars */

const args = (typeof yeet !== "undefined" && yeet.args) || {};
const SECS = Number(args.secs ?? args.s ?? 600);
const SNAPLEN = clampSnap(Number(args.snaplen ?? args.snap ?? 256));

/* `--plain` forces clean stdout: no ANSI color, plain `\n` line endings.
 * Otherwise we auto-detect — colored + raw-mode `\r\n` when a TTY is
 * attached, plain when stdout is piped or redirected. */
const PLAIN = parseBool(args.plain ?? args.p);

/* `--hex` opts back into the full colored hex dump. By default we print
 * only the one-line summary per packet to keep the stream readable. */
const HEX = parseBool(args.hex ?? args.x);

/* `--dir in|out|both` — which side of the interface to tap. Defaults to
 * ingress ("data going in"). */
const DIR = String(args.dir ?? "in").trim().toLowerCase();
const WANT_IN = DIR === "in" || DIR === "both" || DIR === "all";
const WANT_OUT = DIR === "out" || DIR === "both" || DIR === "all";

/* Comma-separated interface indexes (find them with `ip -o link`). When
 * omitted, yeet's TCX attach spec treats the missing field as a wildcard
 * and taps every interface — so leave IFINDEX undefined and let
 * JSON.stringify drop the key on its way to the daemon. */
const IFINDEX = args.ifindex != null
  ? String(args.ifindex)
      .split(",")
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isFinite(n) && n > 0)
  : undefined;

if (!WANT_IN && !WANT_OUT) {
  console.error(
    "usage: yeet run . -- [--ifindex 2,3] [--dir in|out|both] [--snaplen 256] [--secs 600] [--hex]",
  );
  throw new Error(`invalid --dir ${JSON.stringify(DIR)} (want in|out|both)`);
}

function clampSnap(n) {
  if (!Number.isFinite(n) || n <= 0) return 256;
  return Math.min(2047, Math.floor(n)); /* LOAD_MAX in the BPF program */
}

function parseBool(v) {
  if (v == null) return false;
  if (typeof v === "boolean") return v;
  const s = String(v).trim().toLowerCase();
  return s === "" || s === "1" || s === "true" || s === "yes" || s === "on";
}

/* Color only when we're driving a terminal. Piped/redirected output (or
 * an explicit `--plain`) gets bare strings so escape codes don't pollute
 * a saved file or a `grep`. */
const TTY = (typeof globalThis !== "undefined" && globalThis.tty) || null;
const COLOR = !PLAIN && !!(TTY && TTY.write);

const C = (code) => (COLOR ? code : "");
const BOLD = C("\x1b[1m");
const DIM = C("\x1b[2m");
const RED = C("\x1b[31m");
const YEL = C("\x1b[33m");
const GRN = C("\x1b[32m");
const CYAN = C("\x1b[36m");
const BLU = C("\x1b[34m");
const MAG = C("\x1b[35m");
const GRAY = C("\x1b[38;5;244m");
const RESET = C("\x1b[0m");

/* When a TTY is attached the yeet CLI puts it in raw mode (`cfmakeraw`
 * clears `ONLCR`), so the kernel won't translate `\n` → `\r\n` — rewrite
 * line endings so multi-line dumps render cleanly. On plain stdout (pipe
 * or `--plain`) emit unmodified `\n`, which is what a file or pager wants. */
function log(msg = "") {
  const s = String(msg);
  console.log(COLOR ? s.replace(/\r?\n/g, "\r\n") + "\r" : s);
}

const ETHERTYPES = {
  0x0800: "IPv4",
  0x0806: "ARP",
  0x86dd: "IPv6",
  0x8100: "802.1Q",
  0x88cc: "LLDP",
};

const IP_PROTOS = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  47: "GRE",
  50: "ESP",
  58: "ICMPv6",
  89: "OSPF",
  132: "SCTP",
};

function hhmmss() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${ms}`;
}

function fmtBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${(n / 1024 / 1024).toFixed(1)}M`;
}

/* Normalize the kernel payload (Uint8Array or char-flagged string) and
 * trim to the kernel-reported cap_len. */
function payloadBytes(e) {
  const raw = e.payload;
  let u8;
  if (raw == null) {
    u8 = new Uint8Array(0);
  } else if (typeof raw === "string") {
    u8 = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i) & 0xff;
  } else if (raw instanceof Uint8Array) {
    u8 = raw;
  } else {
    u8 = new Uint8Array(raw);
  }
  const len = Math.min(Number(e.cap_len ?? u8.length), u8.length);
  return u8.subarray(0, len);
}

function ipv4(u8, off) {
  return `${u8[off]}.${u8[off + 1]}.${u8[off + 2]}.${u8[off + 3]}`;
}

function ipv6(u8, off) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((u8[off + i] << 8) | u8[off + i + 1]).toString(16));
  }
  /* Collapse the longest run of zero groups to `::`. */
  return parts.join(":").replace(/(^|:)0(:0)+(:|$)/, "::").replace(/:::+/, "::");
}

/* Best-effort decode of L2/L3/L4 for the one-line summary. The capture
 * starts at the MAC header on a clsact hook, but tunnels/loopback may
 * hand us a bare IP packet, so sniff the layout rather than assuming
 * Ethernet. Returns a human string; never throws on short/odd frames. */
function describe(e, u8) {
  const proto = Number(e.protocol) || 0;
  let l3 = -1;
  let ethertype = proto;

  if (u8.length >= 14 && ((u8[12] << 8) | u8[13]) === proto && ETHERTYPES[proto]) {
    l3 = 14; /* Ethernet II */
  } else if (u8.length >= 1 && (u8[0] >> 4) === 4) {
    l3 = 0;
    ethertype = 0x0800;
  } else if (u8.length >= 1 && (u8[0] >> 4) === 6) {
    l3 = 0;
    ethertype = 0x86dd;
  }

  const etName = ETHERTYPES[ethertype] || `0x${ethertype.toString(16).padStart(4, "0")}`;
  if (l3 < 0) return etName;

  if (ethertype === 0x0800 && u8.length >= l3 + 20) {
    const ihl = (u8[l3] & 0x0f) * 4;
    const ipproto = u8[l3 + 9];
    const src = ipv4(u8, l3 + 12);
    const dst = ipv4(u8, l3 + 16);
    return `IPv4 ${ports(u8, l3 + ihl, ipproto, src, dst)}`;
  }

  if (ethertype === 0x86dd && u8.length >= l3 + 40) {
    const ipproto = u8[l3 + 6];
    const src = ipv6(u8, l3 + 8);
    const dst = ipv6(u8, l3 + 24);
    return `IPv6 ${ports(u8, l3 + 40, ipproto, src, dst)}`;
  }

  return etName;
}

/* Render `src → dst` with L4 ports when the protocol carries them. */
function ports(u8, l4, ipproto, src, dst) {
  const name = IP_PROTOS[ipproto] || `proto ${ipproto}`;
  if ((ipproto === 6 || ipproto === 17) && u8.length >= l4 + 4) {
    const sp = (u8[l4] << 8) | u8[l4 + 1];
    const dp = (u8[l4 + 2] << 8) | u8[l4 + 3];
    return `${CYAN}${src}:${sp}${RESET} ${DIM}→${RESET} ${CYAN}${dst}:${dp}${RESET} ${name}`;
  }
  return `${CYAN}${src}${RESET} ${DIM}→${RESET} ${CYAN}${dst}${RESET} ${name}`;
}

/* Per-byte ANSI prefix for the hex column. Printable ASCII reads as the
 * default fg so the eye latches onto it; everything else is dimmed or
 * recolored so noise fades into the background. */
function byteColor(b) {
  if (b === 0x00) return GRAY;
  if (b >= 0x20 && b < 0x7f) return "";
  if (b >= 0x80) return MAG;
  return DIM;
}

function hexdump(u8) {
  let out = "";
  for (let i = 0; i < u8.length; i += 16) {
    let hex = "";
    let hexWidth = 0;
    let asc = "";
    for (let j = 0; j < 16 && i + j < u8.length; j++) {
      const b = u8[i + j];
      const col = byteColor(b);
      const pair = b.toString(16).padStart(2, "0");
      hex += col ? `${col}${pair}${RESET} ` : `${pair} `;
      hexWidth += 3;
      if (j === 7) {
        hex += " ";
        hexWidth += 1;
      }
      asc += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `${DIM}.${RESET}`;
    }
    const pad = " ".repeat(Math.max(0, 49 - hexWidth));
    out += `${DIM}${i.toString(16).padStart(4, "0")}${RESET}  ${hex}${pad}${asc}\n`;
  }
  return out.trimEnd();
}

try {
  let builder = bpf
    .bind("events", { kind: "ringbuf", btf_struct: "pkt_event" })
    .bind(DATA_SEC, { kind: "data" });

  if (WANT_IN) builder = builder.attach("on_ingress", { kind: "tcx", ifindex: IFINDEX });
  if (WANT_OUT) builder = builder.attach("on_egress", { kind: "tcx", ifindex: IFINDEX });

  const control = await builder.start();

  const knobs = new DataSec(control, DATA_SEC);
  const events = new RingBuf(control, "events");

  await knobs.patch({ snaplen: SNAPLEN });

  const ifaceLabel = IFINDEX ? IFINDEX.join(",") : "all";
  const dirLabel = WANT_IN && WANT_OUT ? "in+out" : WANT_IN ? "in" : "out";
  log(
    `${BOLD}ifacesniff${RESET} — tapping ifindex ${BOLD}${ifaceLabel}${RESET} ` +
      `${DIM}(${dirLabel}, snaplen ${SNAPLEN})${RESET}. Ctrl-C to stop.\n`,
  );

  const sub = await events.subscribe((wrapper) => {
    const e = wrapper && wrapper.pkt_event ? wrapper.pkt_event : wrapper || {};
    const u8 = payloadBytes(e);

    const ingress = e.direction === 0;
    const arrow = ingress ? `${GRN}in ${RESET}` : `${YEL}out${RESET}`;
    const wire = Number(e.wire_len ?? u8.length);
    const truncated = u8.length < wire;

    log(
      `${GRAY}${hhmmss()}${RESET} ${arrow} ` +
        `${BOLD}if${e.ifindex}${RESET} ` +
        `${DIM}${fmtBytes(wire)}${truncated ? ` (cap ${fmtBytes(u8.length)})` : ""}${RESET}  ` +
        describe(e, u8),
    );
    if (HEX) {
      if (u8.length > 0) log(hexdump(u8));
      log("");
    }
  });

  await new Promise((r) => setTimeout(r, SECS * 1000));
  await knobs.patch({ enabled: 0 });
  await sub.unsubscribe();
  await control.stop();
} catch (err) {
  console.error(err);
}
