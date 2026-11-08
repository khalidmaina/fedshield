"""Configuration loading. A config file may name a `base:` file; its values are loaded
first and then overridden. Command-line overrides look like  aggregation.rule=krum ."""
import copy
import os

import yaml


def merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def set_dotted(cfg, key, value):
    node = cfg
    parts = key.split(".")
    for p in parts[:-1]:
        if p not in node or not isinstance(node[p], dict):
            node[p] = {}
        node = node[p]
    node[parts[-1]] = value


def load_config(path, overrides=()):
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    if "base" in cfg:
        base_path = cfg.pop("base")
        if not os.path.isabs(base_path):
            base_path = os.path.join(os.path.dirname(os.path.abspath(path)), base_path)
        cfg = merge(load_config(base_path), cfg)
    for item in overrides:
        key, _, raw = item.partition("=")
        set_dotted(cfg, key.strip(), yaml.safe_load(raw))
    return cfg
