"""Who is who in the testbed: hosts, roles, intensities, regions and attacks.

One place for these facts, so the schedule, the dataset and (later) the federated simulation
agree. Must match testbed/docker-compose.yml (checked by a unit test) and decision 0002.
"""

ROLES = ("web", "db", "build", "dev")
HOSTS = tuple(f"fs-{role}-{i}" for role in ROLES for i in (1, 2, 3))
ATTACKS = ("beacon", "cred_access", "miner", "persistence", "scan")
TARGET_ATTACK = "beacon"            # the attack used for normality poisoning (RQ5)

# Workload intensity per host (docker-compose.yml): each role runs at 1, 2 and 3 once.
INTENSITY = {f"fs-{role}-{i}": i for role in ROLES for i in (1, 2, 3)}

# Two regions of six with mixed roles (decision 0002).
REGIONS = {
    "A": ("fs-web-1", "fs-web-2", "fs-db-1", "fs-db-2", "fs-build-1", "fs-dev-1"),
    "B": ("fs-web-3", "fs-db-3", "fs-build-2", "fs-build-3", "fs-dev-2", "fs-dev-3"),
}
REGION_OF = {h: r for r, members in REGIONS.items() for h in members}


def role_of(host):
    """'fs-build-2' -> 'build'."""
    return host.split("-")[1]
