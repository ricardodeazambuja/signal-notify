"""SPQR pure-Python: self-consistency and interop with the Rust ``spqr_py``.

The Rust binding, when built, is an exact oracle: wire messages, derived
message keys, and the serialized protobuf state must all be interchangeable.
Tests that need it skip cleanly when it is absent, leaving the pure-vs-pure
tests as the floor.
"""
import random

import pytest

from signalnotify.native.pure import spqr as PY

AUTH = b"\x29" * 32
MJ = 0xFFFFFFFF
MO = 2000


def _new_pair(mod_a, mod_b):
    return (mod_a.initial_state(AUTH, False, MJ, MO),
            mod_b.initial_state(AUTH, True, MJ, MO))


def _lockstep(mod_a, mod_b, steps=30):
    a, b = _new_pair(mod_a, mod_b)
    saw_key = False
    for step in range(steps):
        a, msg, ka = mod_a.send(a)
        b, kb = mod_b.recv(b, msg)
        assert ka == kb, f"A->B key mismatch at step {step}"
        b, msg, kb = mod_b.send(b)
        a, ka = mod_a.recv(a, msg)
        assert ka == kb, f"B->A key mismatch at step {step}"
        saw_key = saw_key or ka is not None
    assert saw_key, "message keys never materialized"


def test_pure_lockstep():
    _lockstep(PY, PY, steps=40)


def test_pure_out_of_order():
    random.seed(7)
    a, b = _new_pair(PY, PY)
    for _ in range(6):
        a, m, _ = PY.send(a)
        b, _ = PY.recv(b, m)
        b, m, _ = PY.send(b)
        a, _ = PY.recv(a, m)
    burst = []
    for _ in range(10):
        a, m, ka = PY.send(a)
        burst.append((m, ka))
    random.shuffle(burst)
    for m, ka in burst:
        b, kb = PY.recv(b, m)
        assert ka == kb


def test_pure_version0_empty_states():
    # Empty state is treated as V0: send yields empty msg + no key.
    st, msg, key = PY.send(b"")
    assert st == b"" and msg == b"" and key is None


try:
    import spqr_py as rust
except ImportError:  # Rust oracle not built — pure tests above still run.
    rust = None

requires_rust = pytest.mark.skipif(
    rust is None, reason="Rust spqr_py not built (differential oracle)")


@requires_rust
def test_cross_pure_alice_rust_bob():
    _lockstep(PY, rust)


@requires_rust
def test_cross_rust_alice_pure_bob():
    _lockstep(rust, PY)


@requires_rust
def test_state_handoff_rust_to_pure():
    a, b = _new_pair(rust, rust)
    for _ in range(8):
        a, m, ka = rust.send(a)
        b, kb = rust.recv(b, m)
        assert ka == kb
        b, m, kb = rust.send(b)
        a, ka = rust.recv(a, m)
        assert ka == kb
    # Continue the exact same states with the pure implementation.
    for step in range(15):
        a, m, ka = PY.send(a)
        b, kb = PY.recv(b, m)
        assert ka == kb, f"handoff A->B {step}"
        b, m, kb = PY.send(b)
        a, ka = PY.recv(a, m)
        assert ka == kb, f"handoff B->A {step}"


@requires_rust
def test_state_handoff_pure_to_rust():
    a, b = _new_pair(PY, PY)
    for _ in range(8):
        a, m, ka = PY.send(a)
        b, kb = PY.recv(b, m)
        assert ka == kb
        b, m, kb = PY.send(b)
        a, ka = PY.recv(a, m)
        assert ka == kb
    for step in range(15):
        a, m, ka = rust.send(a)
        b, kb = rust.recv(b, m)
        assert ka == kb, f"rev A->B {step}"
        b, m, kb = rust.send(b)
        a, ka = rust.recv(a, m)
        assert ka == kb, f"rev B->A {step}"


@requires_rust
def test_cross_out_of_order():
    random.seed(11)
    a = rust.initial_state(AUTH, False, MJ, MO)
    b = PY.initial_state(AUTH, True, MJ, MO)
    for _ in range(6):
        a, m, _ = rust.send(a)
        b, _ = PY.recv(b, m)
        b, m, _ = PY.send(b)
        a, _ = rust.recv(a, m)
    burst = []
    for _ in range(10):
        a, m, ka = rust.send(a)
        burst.append((m, ka))
    random.shuffle(burst)
    for m, ka in burst:
        b, kb = PY.recv(b, m)
        assert ka == kb


@requires_rust
def test_es_blob_handoff_rust_to_pure():
    """The 2080-byte encapsulation state never crosses the wire, so its
    libcrux byte layout is only exercised when a handoff lands on a state that
    carries it. Drive Rust into CT1_SAMPLED (holding ``es``), hand to pure, and
    require pure's ``encaps2`` to consume Rust's ``es`` bytes correctly."""
    from signalnotify.native.pure.spqr import PqRatchetStatePB, States

    def kind_of(state):
        sp = PqRatchetStatePB.decode(state)
        return "v0" if sp.v1 is None else States.from_pb(sp.v1).kind

    a = rust.initial_state(AUTH, False, MJ, MO)
    b = rust.initial_state(AUTH, True, MJ, MO)
    for _ in range(60):
        a, m, _ = rust.send(a)
        b, _ = rust.recv(b, m)
        b, m, _ = rust.send(b)
        a, _ = rust.recv(a, m)
        if kind_of(b) == "ct1_sampled":
            break
    else:
        pytest.fail("Rust never reached CT1_SAMPLED")

    st = States.from_pb(PqRatchetStatePB.decode(b).v1)
    assert st.kind == "ct1_sampled" and len(st.es) == 2080

    for step in range(20):
        a, m, ka = PY.send(a)
        b, kb = PY.recv(b, m)
        assert ka == kb, f"es-handoff A->B {step}"
        b, m, kb = PY.send(b)
        a, ka = PY.recv(a, m)
        assert ka == kb, f"es-handoff B->A {step}"


@requires_rust
def test_cross_chaos():
    # Randomized send/drop schedule; every delivered message key must agree.
    rng = random.Random(2026)
    a = rust.initial_state(AUTH, False, MJ, MO)
    b = PY.initial_state(AUTH, True, MJ, MO)
    a_out, b_out = [], []          # (msg, key) queues in flight
    for _ in range(400):
        if rng.random() < 0.5:
            a, m, k = rust.send(a)
            a_out.append((m, k))
        if rng.random() < 0.5:
            b, m, k = PY.send(b)
            b_out.append((m, k))
        if a_out and rng.random() < 0.7:
            m, k = a_out.pop(rng.randrange(len(a_out)))
            b, kb = PY.recv(b, m)
            assert k == kb
        if b_out and rng.random() < 0.7:
            m, k = b_out.pop(rng.randrange(len(b_out)))
            a, ka = rust.recv(a, m)
            assert k == ka
