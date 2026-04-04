import networkx as nx

def build_graph(data):
    G = nx.DiGraph()

    for node, neighbors in data.items():
        for neighbor in neighbors:
            G.add_edge(node, neighbor)

    return G