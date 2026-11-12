"""The collection plan: which attacks each host gets in each session, and when (decision 0003).

- 8 sessions, split by session: 1-4 train, 5 val, 6-7 test, 8 holdout (SIEM replay).
- Every host gets 2 attacks per session, one in each half, at random times.
- Train: every host gets beacon twice (in different sessions) and each other attack at least
  once, so any host can be the compromised one in RQ5 and has a beacon pool to poison with.
- Val, test and holdout: every host gets beacon, so all other hosts can be evaluated for RQ5;
  val + test together give every host every other attack too.
- At most ``max_concurrent`` attacks run at once and the CPU-heavy miner never overlaps
  itself, so one attack's load does not change other hosts' normal behaviour.

Pure functions, standard library only; the same seed always gives the same plan.
"""
import random

from .topology import ATTACKS, HOSTS, TARGET_ATTACK

PLAN = {1: "train", 2: "train", 3: "train", 4: "train", 5: "val", 6: "test", 7: "test", 8: "holdout"}
SLOTS = 2                                             # attacks per host per session
OTHERS = tuple(a for a in ATTACKS if a != TARGET_ATTACK)
TARGET_COUNT = {"train": 2, "val": 1, "test": 1, "holdout": 1}
# Where each split starts in the cycle of the other attacks, per host: val {k}, test {k+1..k+3},
# so val + test cover all four for every host; holdout adds one more.
OFFSET = {"train": 0, "val": 0, "test": 1, "holdout": 2}
EXCLUSIVE = ("miner",)                                # never two of these at the same time


def sessions_of(split, plan=PLAN):
    return sorted(s for s, sp in plan.items() if sp == split)


def attacks_for(host, split, n_sessions):
    """The multiset of attacks one host gets across all sessions of one split."""
    k = HOSTS.index(host)
    n_slots = SLOTS * n_sessions
    n_target = min(TARGET_COUNT[split], n_slots)
    start = (k + OFFSET[split]) % len(OTHERS)
    rest = [OTHERS[(start + j) % len(OTHERS)] for j in range(n_slots - n_target)]
    return [TARGET_ATTACK] * n_target + rest


def assign(plan=PLAN, seed=7):
    """{session: {host: [attack in first half, attack in second half]}}."""
    rng = random.Random(seed)
    out = {s: {} for s in plan}
    for split in dict.fromkeys(plan.values()):
        sessions = sessions_of(split, plan)
        for host in HOSTS:
            pool = attacks_for(host, split, len(sessions))
            for _ in range(1000):
                rng.shuffle(pool)
                pairs = [pool[i * SLOTS:(i + 1) * SLOTS] for i in range(len(sessions))]
                # no session gets the same attack twice (so the two beacons land in different sessions)
                if all(len(set(p)) == len(p) for p in pairs):
                    break
            else:
                raise RuntimeError(f"could not spread attacks for {host} in {split}")
            for session, pair in zip(sessions, pairs):
                out[session][host] = pair
    return out


def slot_ranges(duration_min, attack_min):
    """Allowed start ranges (minutes) for the first-half and second-half attack."""
    margin = max(1.0, 0.05 * duration_min)            # quiet start and end
    gap = 0.05 * duration_min                         # quiet middle
    half = duration_min / 2
    a = (margin, half - gap / 2 - attack_min)
    b = (half + gap / 2, duration_min - margin - attack_min)
    if a[1] < a[0] or b[1] < b[0]:
        raise ValueError(f"{attack_min}-minute attacks do not fit twice into {duration_min} minutes")
    return a, b


def _max_overlap(intervals, start, end):
    """Most intervals running at the same moment within [start, end)."""
    points = [start] + [s for s, e in intervals if start < s < end]
    return max((sum(1 for s, e in intervals if s <= p < e) for p in points), default=0)


def place(pairs, duration_min, attack_min, rng, max_concurrent=4):
    """Give every (host, attack) a start time in its half. Returns a list sorted by start."""
    ranges = slot_ranges(duration_min, attack_min)
    placed = []
    for slot, (lo, hi) in enumerate(ranges):
        hosts = list(pairs)
        rng.shuffle(hosts)
        for host in hosts:
            attack = pairs[host][slot]
            for _ in range(2000):
                start = round(rng.uniform(lo, hi) * 4) / 4          # quarter-minute steps
                end = start + attack_min
                busy = [(p["start_min"], p["start_min"] + attack_min) for p in placed]
                if _max_overlap(busy, start, end) + 1 > max_concurrent:
                    continue
                same = [(p["start_min"], p["start_min"] + attack_min) for p in placed
                        if p["attack"] == attack and attack in EXCLUSIVE]
                if _max_overlap(same, start, end) > 0:
                    continue
                placed.append({"host": host, "attack": attack, "start_min": start,
                               "duration_min": attack_min, "slot": slot})
                break
            else:
                raise RuntimeError("could not place all attacks; allow more concurrency or longer sessions")
    return sorted(placed, key=lambda p: (p["start_min"], p["host"]))


def make_schedule(session, plan=PLAN, seed=7, duration_min=120, attack_min=8, max_concurrent=4):
    pairs = assign(plan, seed)[session]
    rng = random.Random(seed * 1000 + session)
    return {"session": session, "split": plan[session], "seed": seed, "duration_min": duration_min,
            "attack_min": attack_min, "max_concurrent": max_concurrent,
            "attacks": place(pairs, duration_min, attack_min, rng, max_concurrent)}


def validate(schedule):
    """Problems with a schedule (empty list = fine). The session runner refuses invalid ones."""
    problems = []
    d = schedule["duration_min"]
    margin = max(1.0, 0.05 * d)
    attacks = schedule["attacks"]
    for host in HOSTS:
        mine = sorted((x["start_min"], x["start_min"] + x["duration_min"]) for x in attacks if x["host"] == host)
        if len(mine) != SLOTS:
            problems.append(f"{host}: {len(mine)} attacks instead of {SLOTS}")
        if any(e1 > s2 for (_, e1), (s2, _) in zip(mine, mine[1:])):
            problems.append(f"{host}: its attacks overlap")
    for x in attacks:
        if x["attack"] not in ATTACKS or x["host"] not in HOSTS:
            problems.append(f"unknown host or attack: {x}")
        if x["start_min"] < margin - 1e-9 or x["start_min"] + x["duration_min"] > d - margin + 1e-9:
            problems.append(f"{x['host']} {x['attack']}: outside the quiet margins")
    spans = [(x["start_min"], x["start_min"] + x["duration_min"]) for x in attacks]
    worst = max((_max_overlap(spans, s, e) for s, e in spans), default=0)
    if worst > schedule["max_concurrent"]:
        problems.append(f"{worst} attacks at once (limit {schedule['max_concurrent']})")
    for kind in EXCLUSIVE:
        same = [(x["start_min"], x["start_min"] + x["duration_min"]) for x in attacks if x["attack"] == kind]
        if any(_max_overlap(same, s, e) > 1 for s, e in same):
            problems.append(f"two {kind} attacks overlap")
    return problems


def coverage(schedules):
    """{host: {split: {attack: count}}} over a set of schedules."""
    out = {h: {} for h in HOSTS}
    for sch in schedules:
        for x in sch["attacks"]:
            split = out[x["host"]].setdefault(sch["split"], {})
            split[x["attack"]] = split.get(x["attack"], 0) + 1
    return out
