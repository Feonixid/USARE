import json
import argparse
import sys
import os
from flask import Flask, render_template_string, jsonify, request # type: ignore
from ops.encryption import Encryptor, load_encrypted # type: ignore

app = Flask(__name__)

# Cyberpunk-styled HTML Template with embedded Vis.js for Network Graphing
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>USARE Visual Intelligence Dashboard</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body { margin: 0; padding: 0; background-color: #0d0d12; color: #00ffcc; font-family: 'Courier New', Courier, monospace; overflow: hidden; }
        #network { width: 100vw; height: 100vh; position: absolute; top: 0; left: 0; z-index: 1; }
        #dashboard { 
            position: absolute; top: 20px; right: 20px; width: 350px; 
            background: rgba(10, 10, 20, 0.85); border: 1px solid #00ffcc; 
            padding: 15px; border-radius: 5px; box-shadow: 0 0 15px rgba(0, 255, 204, 0.3); z-index: 10;
            backdrop-filter: blur(5px);
            max-height: 80vh; overflow-y: auto;
        }
        h1 { font-size: 1.5rem; text-transform: uppercase; margin-top: 0; border-bottom: 1px solid #00ffcc; padding-bottom: 5px; }
        .panel-section { margin-bottom: 15px; border-left: 2px solid #ff0055; padding-left: 10px; }
        .key { font-weight: bold; color: #ff0055; }
        .val { color: #cccccc; }
        .btn { background: #00ffcc; color: #000; border: none; padding: 5px 10px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 10px; }
        .btn:hover { background: #fff; }
        #loading { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2rem; z-index: 100; text-shadow: 0 0 10px #00ffcc; }
        
        /* Node info panel popup */
        #node-info {
            display: none; position: absolute; bottom: 20px; left: 20px; width: 400px;
            background: rgba(15, 10, 30, 0.95); border: 1px solid #ff0055;
            padding: 15px; border-radius: 5px; z-index: 10; box-shadow: 0 0 20px rgba(255, 0, 85, 0.4);
            color: #ddd; max-height: 40vh; overflow-y: auto;
        }
    </style>
</head>
<body>
    <div id="loading">Initializing IntelGraph...</div>
    <div id="network"></div>
    
    <div id="dashboard">
        <h1>USARE CAPSTONE UI</h1>
        <div id="global-stats"></div>
        <button class="btn" onclick="network.fit()">Reset View</button>
    </div>

    <div id="node-info"></div>

    <script>
        let network = null;
        let globalData = null;

        fetch('/api/graph')
            .then(res => res.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                globalData = data;
                
                // Populate Dashboard
                const stats = document.getElementById('global-stats');
                stats.innerHTML = `
                    <div class="panel-section">
                        <div class="key">Target IP:</div><div class="val">${data.metadata.target_ip}</div>
                        <div class="key">Scan Duration:</div><div class="val">${data.metadata.duration_ms.toFixed(0)} ms</div>
                        <div class="key">Start Time:</div><div class="val">${data.metadata.timestamp}</div>
                    </div>
                    <div class="panel-section">
                        <div class="key">Nodes Found:</div><div class="val">${data.graph.nodes.length}</div>
                        <div class="key">Relationships (Edges):</div><div class="val">${data.graph.edges.length}</div>
                    </div>
                `;

                // Render Network
                let nodes_dataset = new vis.DataSet(data.graph.nodes);
                let edges_dataset = new vis.DataSet(data.graph.edges);
                
                let container = document.getElementById('network');
                let graphData = { nodes: nodes_dataset, edges: edges_dataset };
                
                let options = {
                    nodes: { shape: 'dot', size: 20, font: { color: '#ffffff', size: 14 } },
                    edges: { width: 2, font: { color: '#aaaaaa', size: 10 }, color: { color: '#555555', highlight: '#00ffcc' }, smooth: { type: 'continuous' } },
                    physics: { forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 }, maxVelocity: 50, solver: 'forceAtlas2Based', timestep: 0.35, stabilization: { iterations: 150 } },
                    interaction: { hover: true, tooltipDelay: 200 }
                };
                
                network = new vis.Network(container, graphData, options);

                // Handle Node Click
                network.on("click", function (params) {
                    if (params.nodes.length > 0) {
                        const nodeId = params.nodes[0];
                        const node = nodes_dataset.get(nodeId);
                        showNodeInfo(node);
                    } else {
                        document.getElementById('node-info').style.display = 'none';
                    }
                });
            })
            .catch(err => {
                document.getElementById('loading').innerHTML = `<span style="color:red;">Error loading data: ${err}</span>`;
            });

        function showNodeInfo(node) {
            const panel = document.getElementById('node-info');
            panel.style.display = 'block';
            let html = `<h2 style="margin:0; border-bottom:1px solid #ff0055; color:#ff0055;">${node.label} [${node.group}]</h2>`;
            
            // Format nested attributes nicely
            html += `<pre style="white-space: pre-wrap; word-wrap: break-word; font-size: 0.9em;">`;
            if (node.title) {
                try {
                    // Try parsing title if it's JSONized HTML
                    let obj = node.raw_data || node.title;
                    html += JSON.stringify(obj, null, 2).replace(/</g, "&lt;").replace(/>/g, "&gt;");
                } catch(e) {
                    html += node.title; 
                }
            } else {
                html += "No additional metadata.";
            }
            html += `</pre>`;
            panel.innerHTML = html;
        }
    </script>
</body>
</html>
"""

GRAPH_DATA = None

def build_vis_graph(intel_data: dict) -> dict:
    """Converts the raw USARE JSON / IntelGraph output into Vis.js compatible nodes and edges."""
    nodes = []
    edges = []
    
    # Check if we have an IntelGraph object
    if "intel_graph" in intel_data:
        ig = intel_data["intel_graph"]
        
        # Color palettes for cyberpunk feel
        colors = {
            "IP": "#00ffcc",
            "Port": "#ff0055",
            "Domain": "#bb86fc",
            "Certificate": "#03dac6",
            "Vulnerability": "#cf6679",
            "Organization": "#ffb86c",
            "OS": "#8be9fd"
        }

        # Build Nodes
        for n_id, attrs in ig.get("nodes", {}).items():
            n_type = attrs.get("type", "Unknown")
            color = colors.get(n_type, "#ffffff")
            
            # Format title tooltip (HTML)
            title_html = f"<b>Type:</b> {n_type}<br>"
            for k, v in attrs.items():
                if k != "type" and v:
                    title_html += f"<b>{k}:</b> {v}<br>"
                    
            nodes.append({
                "id": n_id,
                "label": str(n_id),
                "group": n_type,
                "title": title_html,
                "color": {"background": color, "border": "#ffffff"},
                "raw_data": attrs
            })
            
        # Build Edges
        edge_id = 0
        for e in ig.get("edges", []):
            edges.append({
                "id": edge_id,
                "from": e["source"],
                "to": e["target"],
                "label": e.get("relationship", ""),
                "arrows": "to" if e.get("relationship") != "resolves_to" else ""
            })
            edge_id += 1
            
        return {
            "nodes": nodes,
            "edges": edges
            }
    
    # Fallback if no intel_graph was actually built, parse basic results 
    # (Just IP -> Ports to have something)
    target = intel_data.get("Target", "Unknown")
    nodes.append({"id": target, "label": target, "group": "IP", "color": "#00ffcc"})
    
    # Vulnerabilities
    vulns = intel_data.get("Vulnerability Research", {})
    if vulns:
        edges.append({"from": target, "to": "Vulns"})
        nodes.append({"id": "Vulns", "label": "Vulnerabilities", "group": "Vulnerability", "color": "#cf6679"})
        
    for p_id, p_data in intel_data.get("Analysis", {}).items():
        if "port" in p_data:
            port_label = f"{p_data['port']}/{p_data.get('protocol', 'tcp')}"
            nodes.append({
                "id": port_label, 
                "label": port_label, 
                "group": "Port", 
                "color": "#ff0055",
                "title": json.dumps(p_data, indent=2)
            })
            edges.append({"from": target, "to": port_label, "label": "has_port"})
            
    return {"nodes": nodes, "edges": edges}

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/graph")
def api_graph():
    global GRAPH_DATA
    if GRAPH_DATA is None:
        return jsonify({"error": "No data loaded"}), 404
        
    vis_data = build_vis_graph(GRAPH_DATA)
    return jsonify({
        "metadata": {
            "target_ip": GRAPH_DATA.get("Target", "Unknown"),
            "timestamp": GRAPH_DATA.get("Generated", "Unknown"),
            "duration_ms": GRAPH_DATA.get("Total_Duration_ms", 0.0)
        },
        "graph": vis_data,
        "raw_stats": {
            "heat_level": GRAPH_DATA.get("Heat Level", "Unknown")
        }
    })

def main():
    parser = argparse.ArgumentParser(description="USARE Visual Intelligence Dashboard")
    parser.add_argument("encrypted_file", help="Path to usare_results.enc", default="usare_results.enc", nargs='?')
    parser.add_argument("--port", type=int, default=5000, help="Web server port")
    args = parser.parse_args()

    if not os.path.exists(args.encrypted_file):
        print(f"Error: Encrypted file '{args.encrypted_file}' not found.")
        sys.exit(1)

    print(f"Loading encrypted scan data from {args.encrypted_file}...")
    try:
        from getpass import getpass
        password = getpass("Enter decryption password: ")
        global GRAPH_DATA
        GRAPH_DATA = load_encrypted(args.encrypted_file, password)
        print("Data successfully decrypted and loaded into visualizer.")
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

    print(f"Starting UI Interface... Open http://localhost:{args.port} in your browser.")
    app.run(host="127.0.0.1", port=args.port, debug=False)

if __name__ == "__main__":
    main()
