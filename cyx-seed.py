#!/usr/bin/env python3
"""
CYTHANX-RX: synthetic RandomX-style proof-of-work variant.

Design:
  seed/header -> CYTHANX organism mutation -> lane mixing -> RandomX-like
  memory-hard transform -> final digest.

This is NOT compatible with Monero RandomX or XMRig pools. It is a
self-contained experimental PoW variant intended for local/test networks.
"""

import argparse
import hashlib
import os
import struct
import time
from dataclasses import dataclass

try:
    import blake3
except ImportError:
    blake3 = None

DOMAIN = b"CYTHANX-RX/V1"

# ---------------------------------------------------------------------------
# Automated seed + lineage fingerprint
# ---------------------------------------------------------------------------
# "auto" creates a cryptographically random root seed once and persists it.
# The fingerprint is a deterministic lineage identifier derived only from
# CYTHANX data; it does not fingerprint the user's hardware or network.
# ---------------------------------------------------------------------------

SEED_BYTES = 32
DEFAULT_SEED_FILE = "cythanx.seed"


def _normalize_seed_text(seed_text: str) -> bytes:
    value = seed_text.strip()
    if not value:
        raise ValueError("seed must not be empty")
    return value.encode("utf-8")


def load_or_create_seed(seed_text: str, seed_file: str = DEFAULT_SEED_FILE) -> tuple[str, bytes]:
    """Return a stable seed; 'auto' creates it once and reuses it thereafter."""
    if seed_text.strip().lower() != "auto":
        raw = _normalize_seed_text(seed_text)
        return seed_text, raw

    path = os.path.abspath(os.path.expanduser(seed_file))
    try:
        with open(path, "rb") as f:
            raw = f.read().strip()
        if len(raw) != SEED_BYTES * 2:
            raise ValueError("invalid persisted seed")
        # Hex is used so the seed file is portable and unambiguous.
        seed_hex = raw.decode("ascii")
        bytes.fromhex(seed_hex)
    except (FileNotFoundError, ValueError, UnicodeDecodeError):
        raw_bytes = os.urandom(SEED_BYTES)
        seed_hex = raw_bytes.hex()
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="ascii") as f:
            f.write(seed_hex + "\n")
        os.replace(tmp, path)
        raw = raw_bytes
    else:
        raw = bytes.fromhex(seed_hex)
    return seed_hex, raw


def lineage_fingerprint(seed: bytes, state: bytes, generation: int,
                        genesis: bytes = b"") -> str:
    """Create a deterministic 256-bit fingerprint for this CYTHANX lineage."""
    payload = (
        DOMAIN + b"|FINGERPRINT|"
        + struct.pack("<I", generation & 0xffffffff)
        + seed
        + state
        + genesis
    )
    return b3(payload).hex()


def seed_fingerprint(seed: bytes) -> str:
    """Fingerprint the root seed without exposing or storing the raw seed."""
    return b3(DOMAIN + b"|SEED-FINGERPRINT|" + seed).hex()

MEMORY_WORDS = 4096          # 32 KiB working set
ROUNDS = 256


def h256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b3(data: bytes) -> bytes:
    if blake3 is not None:
        return blake3.blake3(data).digest()
    return hashlib.blake2s(data).digest()


def joaat(data: bytes) -> int:
    h = 0
    for x in data:
        h = (h + x) & 0xffffffff
        h = (h + ((h << 10) & 0xffffffff)) & 0xffffffff
        h ^= h >> 6
    h = (h + ((h << 3) & 0xffffffff)) & 0xffffffff
    h ^= h >> 11
    h = (h + ((h << 15) & 0xffffffff)) & 0xffffffff
    return h


@dataclass
class Organism:
    generation: int
    entropy: int
    energy: int
    state: bytes


def mutate_organism(seed: bytes, rounds: int = 8) -> Organism:
    state = b3(DOMAIN + b"|GENESIS|" + seed)
    energy = int.from_bytes(state[:4], "little")
    entropy = int.from_bytes(state[4:8], "little")
    generation = 0

    for generation in range(1, rounds + 1):
        j = joaat(state + struct.pack("<II", energy, entropy))
        branch = j & 3

        if branch == 0:
            state = b3(state + seed + struct.pack("<I", j))
        elif branch == 1:
            state = h256(state[::-1] + seed + struct.pack("<I", j))
        elif branch == 2:
            state = b3(seed + state + struct.pack("<Q", j * 0x9E3779B1))
        else:
            state = h256(b3(state + DOMAIN) + seed)

        energy = ((energy << 5) ^ (energy >> 2) ^ j) & 0xffffffff
        entropy = (entropy + joaat(state[:16]) + generation) & 0xffffffff

    return Organism(generation, entropy, energy, state)


def build_memory(header: bytes, organism: Organism) -> bytearray:
    root = b3(DOMAIN + header + organism.state)
    mem = bytearray(MEMORY_WORDS * 8)

    for i in range(MEMORY_WORDS):
        x = b3(root + struct.pack("<I", i) + organism.state)
        mem[i * 8:(i + 1) * 8] = x[:8]

    return mem


def cythanx_rx(header: bytes, seed: bytes, rounds: int = ROUNDS) -> bytes:
    org = mutate_organism(seed)

    # CYTHANX mutation becomes the initial execution key.
    key = b3(org.state + struct.pack("<II", org.energy, org.entropy))
    mem = build_memory(header, org)

    a = int.from_bytes(key[0:8], "little")
    b = int.from_bytes(key[8:16], "little")
    c = int.from_bytes(key[16:24], "little")
    d = int.from_bytes(key[24:32], "little")

    for i in range(rounds):
        # Data-dependent memory access gives the transform a memory-hard shape.
        idx = ((a ^ c ^ (i * 0x9E3779B9)) % MEMORY_WORDS)
        off = idx * 8
        m = int.from_bytes(mem[off:off + 8], "little")

        a = (a + m + d) & 0xffffffffffffffff
        b = ((b ^ a) * 0x9E3779B97F4A7C15) & 0xffffffffffffffff
        c = (c + ((b << 13) | (b >> 51))) & 0xffffffffffffffff
        d ^= (c + 0xD6E8FEB86659FD93) & 0xffffffffffffffff

        mem[off:off + 8] = ((m ^ a ^ c) & 0xffffffffffffffff).to_bytes(8, "little")

        if i % 32 == 0:
            key = b3(key + struct.pack("<QQQQ", a, b, c, d))

    final = (
        DOMAIN
        + header
        + org.state
        + struct.pack("<QQQQ", a, b, c, d)
        + bytes(mem[idx * 8:(idx + 1) * 8])
    )
    return b3(final)


def synthetic_genesis(seed_text: str) -> dict:
    seed = seed_text.encode()
    org = mutate_organism(seed)
    genesis = h256(DOMAIN + b"|GENESIS|" + seed + org.state)
    miracle = b3(DOMAIN + b"|MIRACLE|" + genesis + org.state).hex()
    return {
        "seed": seed_text,
        "genesis": genesis.hex(),
        "joatt": f"{joaat(org.state):08x}",
        "generation": org.generation,
        "miracle": "MIRACLE-" + miracle,
    }


def self_test() -> None:
    h = b"CYTHANX test header"
    s = b"CYTHANX"
    x = cythanx_rx(h, s)
    y = cythanx_rx(h, s)
    assert x == y
    assert len(x) == 32
    print("SELF-TEST: PASS")
    print("digest:", x.hex())


def main():
    p = argparse.ArgumentParser(description="CYTHANX synthetic RandomX-style PoW")
    p.add_argument(
        "--seed",
        default="CYTHANX",
        help="seed text, or 'auto' to create/reuse a persistent random seed",
    )
    p.add_argument("--seed-file", default=DEFAULT_SEED_FILE)
    p.add_argument("--header", default="")
    p.add_argument("--rounds", type=int, default=ROUNDS)
    p.add_argument("--nonce-start", type=int, default=0)
    p.add_argument("--nonce-count", type=int, default=1)
    p.add_argument("--difficulty-prefix", default="")
    p.add_argument("--genesis", action="store_true")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()

    if args.self_test:
        self_test()
        return

    if args.genesis:
        import json
        seed_label, _seed = load_or_create_seed(args.seed, args.seed_file)
        result = synthetic_genesis(seed_label)
        result["seed_fingerprint"] = seed_fingerprint(_seed)
        print(json.dumps(result, indent=2))
        return

    seed_label, seed = load_or_create_seed(args.seed, args.seed_file)
    header = args.header.encode()

    print("CYTHANX-RX / V1")
    print("seed:", seed_label)
    print("seed_fingerprint:", seed_fingerprint(seed))
    print("header:", args.header)

    for nonce in range(args.nonce_start, args.nonce_start + args.nonce_count):
        work = header + struct.pack("<Q", nonce)
        digest = cythanx_rx(work, seed, args.rounds)
        hx = digest.hex()

        print(f"nonce={nonce} digest={hx}")

        if args.difficulty_prefix and hx.startswith(args.difficulty_prefix):
            print(f"FOUND nonce={nonce} digest={hx}")
            return


# ---------------------------------------------------------------------------
# XMRig interweave controller
# ---------------------------------------------------------------------------
# CYTHANX evolves the worker lineage; XMRig remains the actual RandomX engine.
# A new mutation produces a new deterministic rig identity. Because XMRig's
# command-line identity is established at process start, the controller
# restarts XMRig at mutation boundaries rather than attempting to modify the
# RandomX implementation in-place.
# ---------------------------------------------------------------------------

import json
import shutil
import signal
import subprocess
import threading


class CythanxXmrigInterweave:
    def __init__(
        self,
        xmrig="xmrig",
        pool=None,
        user=None,
        password="x",
        algo="rx/0",
        seed="CYTHANX",
        mutation_interval=300,
        threads=None,
        tls=False,
        extra_args=None,
    ):
        self.xmrig = xmrig
        self.pool = pool
        self.user = user
        self.password = password
        self.algo = algo
        self.seed = seed
        self.mutation_interval = max(30, mutation_interval)
        self.threads = threads
        self.tls = tls
        self.extra_args = extra_args or []
        self.proc = None
        self.stop_event = threading.Event()
        self.generation = 0
        self.lineage = None
        self.seed_label = seed
        self.seed_bytes = _normalize_seed_text(seed)
        self.root_fingerprint = seed_fingerprint(self.seed_bytes)

    def _mutation(self):
        # Evolve the organism from the previous lineage instead of using
        # unrelated random identifiers.
        prior = self.seed_bytes
        if self.lineage:
            prior += bytes.fromhex(self.lineage["state"])
        org = mutate_organism(prior, rounds=8)

        genesis = h256(DOMAIN + b"|XMRIG-GENESIS|" + prior + org.state)
        miracle = b3(
            DOMAIN
            + b"|XMRIG-MIRACLE|"
            + genesis
            + org.state
            + struct.pack("<II", org.energy, org.entropy)
        ).hex()

        self.generation += 1
        fingerprint = lineage_fingerprint(
            self.seed_bytes, org.state, self.generation, genesis
        )
        self.lineage = {
            "generation": self.generation,
            "state": org.state.hex(),
            "energy": org.energy,
            "entropy": org.entropy,
            "joaat": f"{joaat(org.state):08x}",
            "genesis": genesis.hex(),
            "fingerprint": fingerprint,
            "root_fingerprint": self.root_fingerprint,
            "miracle": "CYX-" + miracle[:48],
        }
        return self.lineage

    def _rig_id(self, lineage):
        # XMRig accepts this as worker metadata; it does not change RandomX.
        return f"CYX-G{lineage['generation']}-{lineage['fingerprint'][:32]}"

    def build_command(self, lineage):
        exe = shutil.which(self.xmrig) or self.xmrig
        cmd = [
            exe,
            "--algo", self.algo,
            "--url", self.pool,
            "--user", self.user,
            "--pass", self.password,
            "--rig-id", self._rig_id(lineage),
            "--keepalive",
            "--print-time", "10",
            "--health-print-time", "30",
        ]
        if self.tls:
            cmd.append("--tls")
        if self.threads:
            cmd += ["--threads", str(self.threads)]
        cmd += self.extra_args
        return cmd

    def run(self):
        if not self.pool or not self.user:
            raise ValueError("--pool and --user are required")

        print("CYTHANX ↔ XMRig interweave active")
        print("RandomX engine: XMRig")
        print("Mutation layer: CYTHANX")

        while not self.stop_event.is_set():
            lineage = self._mutation()
            cmd = self.build_command(lineage)

            safe_cmd = list(cmd)
            if "--pass" in safe_cmd:
                i = safe_cmd.index("--pass")
                if i + 1 < len(safe_cmd):
                    safe_cmd[i + 1] = "***"

            print(json.dumps({
                "event": "mutation",
                "generation": lineage["generation"],
                "genesis": lineage["genesis"],
                "joatt": lineage["joatt"],
                "miracle": lineage["miracle"],
                "xmrig_rig_id": self._rig_id(lineage),
                "command": safe_cmd,
            }, sort_keys=True))

            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            deadline = time.monotonic() + self.mutation_interval
            try:
                while self.proc.poll() is None and not self.stop_event.is_set():
                    line = self.proc.stdout.readline()
                    if line:
                        print("[XMRIG]", line.rstrip())
                    if time.monotonic() >= deadline:
                        print(
                            f"[CYTHANX] mutation boundary reached: "
                            f"generation {lineage['generation']}"
                        )
                        break
            finally:
                if self.proc.poll() is None:
                    self.proc.send_signal(signal.SIGINT)
                    try:
                        self.proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait()

                self.proc = None

        print("CYTHANX ↔ XMRig interweave stopped")


def interweave_main():
    p = argparse.ArgumentParser(
        description="Intertwine CYTHANX evolution with an XMRig RandomX worker"
    )
    p.add_argument("--xmrig", default="xmrig")
    p.add_argument("--pool", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", default="x")
    p.add_argument("--algo", default="rx/0")
    p.add_argument(
        "--seed",
        default="auto",
        help="seed text, or 'auto' to create/reuse a persistent random seed",
    )
    p.add_argument(
        "--seed-file",
        default=DEFAULT_SEED_FILE,
        help="path for the persistent auto-seed",
    )
    p.add_argument("--mutation-interval", type=int, default=300)
    p.add_argument("--threads", type=int)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--extra", nargs="*", default=[])
    args = p.parse_args()

    seed_label, seed_bytes = load_or_create_seed(args.seed, args.seed_file)
    controller = CythanxXmrigInterweave(
        xmrig=args.xmrig,
        pool=args.pool,
        user=args.user,
        password=args.password,
        algo=args.algo,
        seed=seed_label,
        mutation_interval=args.mutation_interval,
        threads=args.threads,
        tls=args.tls,
        extra_args=args.extra,
    )
    controller.seed_bytes = seed_bytes
    controller.root_fingerprint = seed_fingerprint(seed_bytes)

    def stop(_sig, _frame):
        controller.stop_event.set()
        if controller.proc and controller.proc.poll() is None:
            controller.proc.send_signal(signal.SIGINT)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    controller.run()


# Preserve the original standalone CYTHANX-RX interface above.  The XMRig
# interweave controller is selected explicitly through the environment or
# by calling interweave_main() from a small launcher.


if __name__ == "__main__":
    # XMRIG_INTERWEAVE=1 selects the XMRig controller.
    # Otherwise the original CYTHANX-RX CLI is preserved.
    if os.environ.get("XMRIG_INTERWEAVE") == "1":
        interweave_main()
    else:
        main()
