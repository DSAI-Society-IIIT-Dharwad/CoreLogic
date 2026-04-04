import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8001';

function App() {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);

  const runAnalysis = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`/api/analyze`);
      setAnalysis(response.data);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <header className="mb-8">
        <h1 className="text-4xl font-bold mb-4">
          Cluster<span className="text-blue-400">Nodes</span>
        </h1>
        <button
          onClick={runAnalysis}
          disabled={loading}
          className="px-6 py-3 bg-blue-500 rounded-lg font-semibold hover:bg-blue-600 disabled:opacity-50"
        >
          {loading ? 'Analyzing...' : 'Run Analysis'}
        </button>
      </header>

      {analysis && (
        <div className="space-y-6">
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-gray-800 p-6 rounded-lg">
              <div className="text-sm text-gray-400 mb-2">Risk Level</div>
              <div className="text-3xl font-bold text-red-500">
                {analysis.summary?.risk_level || 'N/A'}
              </div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg">
              <div className="text-sm text-gray-400 mb-2">Attack Paths</div>
              <div className="text-3xl font-bold">
                {analysis.summary?.total_attack_paths || 0}
              </div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg">
              <div className="text-sm text-gray-400 mb-2">Vulnerable Pods</div>
              <div className="text-3xl font-bold text-orange-500">
                {analysis.summary?.vulnerable_pods || 0}
              </div>
            </div>
            <div className="bg-gray-800 p-6 rounded-lg">
              <div className="text-sm text-gray-400 mb-2">Critical Nodes</div>
              <div className="text-3xl font-bold">
                {analysis.summary?.critical_nodes_count || 0}
              </div>
            </div>
          </div>

          <div className="bg-gray-800 p-6 rounded-lg">
            <h2 className="text-xl font-bold mb-4">Analysis Complete!</h2>
            <p className="text-gray-300">
              Security analysis completed successfully. Check the metrics above.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
