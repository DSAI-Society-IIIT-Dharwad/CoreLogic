import networkx as nx

def detect_cycles(G):
    return list(nx.simple_cycles(G))

def get_reachable_nodes(G, start):
    return list(nx.single_source_shortest_path(G, start).keys())

def simulate_attack(path):
    steps = []

    for i, node in enumerate(path):
        if i == 0:
            steps.append(f"Step {i+1}: {node} compromised")
        else:
            steps.append(f"Step {i+1}: Access {node}")

    return steps

def calculate_risk(path):
    if len(path) > 4:
        return "HIGH"
    elif len(path) >= 3:
        return "MEDIUM"
    else:
        return "LOW"

def suggest_fix(path):
    if len(path) > 2:
        return f"Consider restricting access at '{path[1]}' to break the attack path"
    return "No major risk detected"

def get_attack_path(G, start, target):
    try:
        return nx.shortest_path(G, start, target)
    except:
        return []