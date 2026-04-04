"""Command-line interface for ClusterNodes using Typer"""
import typer
import json
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from typing import Optional

app = typer.Typer(
    name="clusternodes",
    help="Kubernetes Security Analysis Tool - CLI",
    add_completion=False,
)

console = Console()
API_BASE = "http://localhost:8001/api"


@app.command()
def analyze():
    """
    Run comprehensive security analysis on the cluster
    """
    console.print("[bold blue]Running ClusterNodes Security Analysis...[/bold blue]")
    
    try:
        response = requests.get(f"{API_BASE}/analyze")
        response.raise_for_status()
        
        data = response.json()
        analysis = data.get("analysis", {})
        summary = data.get("summary", {})
        
        # Display summary
        console.print(f"\\n[bold green]✓ Analysis Complete[/bold green]")
        console.print(f"\\n[bold]Risk Level: [{get_risk_color(summary.get('risk_level'))}]{summary.get('risk_level')}[/{get_risk_color(summary.get('risk_level'))}][/bold]")
        
        # Create metrics table
        table = Table(title="Security Metrics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", justify="right", style="magenta")
        
        table.add_row("Total Attack Paths", str(summary.get("total_attack_paths", 0)))
        table.add_row("Critical Paths", str(summary.get("critical_paths", 0)))
        table.add_row("Vulnerable Pods", str(summary.get("vulnerable_pods", 0)))
        table.add_row("Critical Nodes", str(summary.get("critical_nodes_count", 0)))
        
        console.print(table)
        
        # Show top critical paths
        attack_paths = analysis.get("attack_paths", {}).get("top_10_critical", [])
        if attack_paths:
            console.print("\\n[bold]Top 3 Critical Attack Paths:[/bold]")
            for i, path in enumerate(attack_paths[:3], 1):
                console.print(f"  {i}. {path.get('entry_point')} → {path.get('crown_jewel')} "
                            f"([{get_risk_color(path.get('severity'))}]{path.get('severity')}[/{get_risk_color(path.get('severity'))}])")
        
        console.print("\\n[dim]Run 'clusternodes report' to generate detailed PDF report[/dim]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def graph():
    """
    Display graph statistics
    """
    try:
        response = requests.get(f"{API_BASE}/graph")
        response.raise_for_status()
        
        data = response.json()
        stats = data.get("statistics", {})
        
        console.print("[bold]Cluster Graph Statistics:[/bold]\\n")
        
        console.print(f"Total Nodes: {stats.get('total_nodes')}")
        console.print(f"Total Edges: {stats.get('total_edges')}")
        console.print(f"Graph Density: {stats.get('density', 0):.4f}")
        console.print(f"Is DAG: {stats.get('is_dag')}")
        
        console.print("\\n[bold]Nodes by Type:[/bold]")
        for node_type, count in stats.get("nodes_by_type", {}).items():
            console.print(f"  {node_type}: {count}")
        
        console.print("\\n[bold]Entry Points:[/bold]")
        for ep in stats.get("entry_points", [])[:5]:
            console.print(f"  • {ep.get('name')} ({ep.get('type')})")
        
        console.print("\\n[bold]Crown Jewels:[/bold]")
        for cj in stats.get("crown_jewels", [])[:5]:
            console.print(f"  • {cj.get('name')} (Risk: {cj.get('risk_score')})")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def blast_radius(
    node_id: str = typer.Argument(..., help="Node ID to analyze"),
    max_hops: Optional[int] = typer.Option(None, "--max-hops", "-m", help="Maximum hops to analyze")
):
    """
    Calculate blast radius from a specific node
    """
    console.print(f"[bold blue]Calculating blast radius for node: {node_id}[/bold blue]\\n")
    
    try:
        url = f"{API_BASE}/blast-radius/{node_id}"
        params = {"max_hops": max_hops} if max_hops else {}
        
        response = requests.get(url, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        console.print(f"[bold]Start Node:[/bold] {data.get('start_node_name')}")
        console.print(f"[bold]Total Reachable:[/bold] {data.get('total_reachable')}")
        console.print(f"[bold]Severity:[/bold] [{get_risk_color(data.get('severity'))}]{data.get('severity')}[/{get_risk_color(data.get('severity'))}]")
        
        crown_jewels = data.get("crown_jewels_reached", [])
        if crown_jewels:
            console.print(f"\\n[bold red]⚠ Crown Jewels Accessible: {len(crown_jewels)}[/bold red]")
            for cj in crown_jewels[:5]:
                console.print(f"  • {cj.get('name')}")
        
        console.print("\\n[bold]Reachable Nodes by Type:[/bold]")
        for node_type, count in data.get("breakdown_by_type", {}).items():
            console.print(f"  {node_type}: {count}")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def simulate(
    node_id: str = typer.Argument(..., help="Entry point node ID to simulate from")
):
    """
    Simulate an attack from an entry point
    """
    console.print(f"[bold blue]Simulating attack from: {node_id}[/bold blue]\\n")
    
    try:
        response = requests.get(f"{API_BASE}/simulate/{node_id}")
        response.raise_for_status()
        
        data = response.json()
        
        console.print(f"[bold]Entry Point:[/bold] {data.get('entry_point_name')}")
        console.print(f"[bold]Attack Success Probability:[/bold] {data.get('attack_success_probability', 0) * 100:.1f}%\\n")
        
        paths = data.get("paths_to_crown_jewels", [])
        if paths:
            console.print(f"[bold red]⚠ {len(paths)} Path(s) to Crown Jewels Found![/bold red]\\n")
            
            for i, path in enumerate(paths[:5], 1):
                console.print(f"[bold]Path {i}:[/bold]")
                console.print(f"  Target: {path.get('target')}")
                console.print(f"  Hops: {path.get('path_length')}")
                console.print(f"  Severity: [{get_risk_color(path.get('severity'))}]{path.get('severity')}[/{get_risk_color(path.get('severity'))}]")
                console.print()
        else:
            console.print("[green]✓ No direct paths to crown jewels found[/green]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def critical():
    """
    Display critical nodes that break multiple attack paths
    """
    console.print("[bold blue]Analyzing Critical Nodes...[/bold blue]\\n")
    
    try:
        response = requests.get(f"{API_BASE}/critical-nodes")
        response.raise_for_status()
        
        data = response.json()
        nodes = data.get("critical_nodes", [])
        
        if not nodes:
            console.print("[green]✓ No critical nodes identified[/green]")
            return
        
        console.print(f"[bold]Total Critical Nodes:[/bold] {len(nodes)}\\n")
        
        table = Table(title="Top Critical Nodes")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="magenta")
        table.add_column("Paths Broken", justify="right", style="yellow")
        table.add_column("Impact %", justify="right", style="red")
        
        for node in nodes[:10]:
            table.add_row(
                node.get("name", ""),
                node.get("type", ""),
                str(node.get("paths_broken", 0)),
                f"{node.get('impact_percentage', 0):.1f}%"
            )
        
        console.print(table)
        
        console.print("\\n[dim]Removing these nodes will significantly reduce attack surface[/dim]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def cve():
    """
    Display CVE vulnerability scan results
    """
    console.print("[bold blue]CVE Vulnerability Scan Results...[/bold blue]\\n")
    
    try:
        response = requests.get(f"{API_BASE}/cve-scan")
        response.raise_for_status()
        
        data = response.json()
        
        console.print(f"[bold]Pods Scanned:[/bold] {data.get('total_pods_scanned')}")
        console.print(f"[bold]Vulnerable Pods:[/bold] {data.get('vulnerable_pods_count')}")
        console.print(f"[bold]Average CVSS Score:[/bold] {data.get('average_cvss_score', 0):.2f}")
        console.print(f"[bold]Overall Risk:[/bold] [{get_risk_color(data.get('overall_risk'))}]{data.get('overall_risk')}[/{get_risk_color(data.get('overall_risk'))}]\\n")
        
        console.print("[bold]Severity Distribution:[/bold]")
        for severity, count in data.get("severity_distribution", {}).items():
            console.print(f"  {severity}: {count}")
        
        vulnerable_pods = data.get("vulnerable_pods", [])
        if vulnerable_pods:
            console.print("\\n[bold]Top Vulnerable Pods:[/bold]")
            for pod in vulnerable_pods[:5]:
                console.print(f"  • {pod.get('pod_name')} - {pod.get('cve_id')} "
                            f"(CVSS: {pod.get('cvss_score')})")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def report():
    """
    Generate comprehensive PDF report
    """
    console.print("[bold blue]Generating PDF Report...[/bold blue]\\n")
    
    try:
        response = requests.get(f"{API_BASE}/report/pdf")
        response.raise_for_status()
        
        filename = "clusternodes_report.pdf"
        with open(filename, "wb") as f:
            f.write(response.content)
        
        console.print(f"[bold green]✓ Report generated: {filename}[/bold green]")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def snapshot():
    """
    Create a new cluster snapshot
    """
    console.print("[bold blue]Creating Snapshot...[/bold blue]\\n")
    
    try:
        response = requests.post(f"{API_BASE}/snapshot")
        response.raise_for_status()
        
        data = response.json()
        console.print(f"[bold green]✓ {data.get('message')}[/bold green]")
        console.print(f"[bold]Snapshot ID:[/bold] {data.get('snapshot_id')}")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def snapshots():
    """
    List all available snapshots
    """
    console.print("[bold blue]Available Snapshots:[/bold blue]\\n")
    
    try:
        response = requests.get(f"{API_BASE}/snapshots")
        response.raise_for_status()
        
        data = response.json()
        snaps = data.get("snapshots", [])
        
        if not snaps:
            console.print("[yellow]No snapshots found[/yellow]")
            return
        
        table = Table(title=f"Snapshots ({data.get('total')})")
        table.add_column("ID", style="cyan")
        table.add_column("Timestamp", style="magenta")
        table.add_column("Risk Level", style="yellow")
        
        for snap in snaps[:20]:
            table.add_row(
                snap.get("id", ""),
                snap.get("timestamp", ""),
                snap.get("metadata", {}).get("risk_level", "UNKNOWN")
            )
        
        console.print(table)
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


@app.command()
def diff(
    snapshot1: str = typer.Argument(..., help="First snapshot ID"),
    snapshot2: str = typer.Argument(..., help="Second snapshot ID")
):
    """
    Compare two snapshots
    """
    console.print("[bold blue]Comparing Snapshots...[/bold blue]\\n")
    
    try:
        response = requests.post(
            f"{API_BASE}/diff",
            json={"snapshot_id1": snapshot1, "snapshot_id2": snapshot2}
        )
        response.raise_for_status()
        
        data = response.json()
        
        console.print(f"[bold]Snapshot 1:[/bold] {data.get('snapshot1_id')} ({data.get('snapshot1_time')})")
        console.print(f"[bold]Snapshot 2:[/bold] {data.get('snapshot2_id')} ({data.get('snapshot2_time')})\\n")
        
        changes = data.get("changes", {})
        
        console.print("[bold]Changes Detected:[/bold]\\n")
        
        for metric, change_data in changes.items():
            if isinstance(change_data, dict) and "before" in change_data:
                delta_str = ""
                if "delta" in change_data:
                    delta = change_data["delta"]
                    delta_str = f" ({'+' if delta >= 0 else ''}{delta})"
                
                console.print(f"  {metric.replace('_', ' ').title()}:")
                console.print(f"    Before: {change_data.get('before')}")
                console.print(f"    After: {change_data.get('after')}{delta_str}")
                console.print()
        
        console.print(f"[bold]Summary:[/bold] {data.get('summary')}")
        
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]✗ Error: {e}[/bold red]")
        raise typer.Exit(code=1)


def get_risk_color(severity: str) -> str:
    """Get color based on severity"""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "dim"
    }
    return colors.get(severity, "white")


if __name__ == "__main__":
    app()
