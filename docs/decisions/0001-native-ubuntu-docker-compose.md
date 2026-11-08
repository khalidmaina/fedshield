# 0001. Native Ubuntu 24.04 with Docker Compose

- Status: accepted
- Date: 2026-11-08
- Deciders: Hasib, Khalid

## Context

eBPF needs a Linux kernel. The original guide used a VMware VM on Windows with 8 of 16 GB RAM, and the hosts could be
run with Docker Compose or Kubernetes.

## Options

1. Ubuntu VM in VMware on Windows.
2. WSL2.
3. Ubuntu installed natively.
4. Kubernetes (k3s) instead of Docker Compose for the hosts.

## Decision

Ubuntu **24.04 LTS** installed natively, hosts run with **Docker Compose**. Not 26.04: the pinned libraries
(numpy 1.26.4, torch 2.5.1) need Python 3.12, which 24.04 ships.

## Consequences

- All RAM and cores go to the project; eBPF runs on a real kernel; overhead numbers are cleaner.
- WSL2 is avoided (missing BTF and tracepoints make bpftrace unreliable there).
- Kubernetes is avoided: it adds no value to the research questions, costs 0.5-1 GB RAM, and would invite confusion
  with FedMon, which is Kubernetes-based. Recorded as "won't" in the plan.
