from fastapi import FastAPI
import json
from graph_utils import build_graph
from algorithms import (
    get_reachable_nodes,
    get_attack_path,
    detect_cycles,
    simulate_attack,
    calculate_risk,
    suggest_fix
)

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Attack Analyzer Running"}

@app.get("/analyze")
def analyze():
    with open("data.json") as f:
        data = json.load(f)

    G = build_graph(data)

    start = "Pod-A"
    target = "Database"

    path = get_attack_path(G, start, target)

    return {
        "reachable": get_reachable_nodes(G, start),
        "attack_path": path,
        "simulation": simulate_attack(path),
        "risk": calculate_risk(path),
        "fix": suggest_fix(path),
        "cycles": detect_cycles(G)
    }