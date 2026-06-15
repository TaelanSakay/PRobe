import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Loader, Trash2, Brain } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Scan, RepoMemory } from './types';

export default function RepoDetail() {
  const { repoId } = useParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [memory, setMemory] = useState<RepoMemory[]>([]);
  const [repoInfo, setRepoInfo] = useState<{name: string, owner: string} | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!repoId) return;
    
    Promise.all([
      fetch(`http://localhost:8000/repos/${repoId}/scans`).then(res => res.json()),
      fetch(`http://localhost:8000/repos/${repoId}/memory`).then(res => res.json())
    ]).then(([scansData, memoryData]) => {
      setScans(scansData.scans || []);
      if (scansData.repo) setRepoInfo(scansData.repo);
      setMemory(memoryData.memory || []);
      setLoading(false);
    }).catch(err => {
      console.error(err);
      setLoading(false);
    });
  }, [repoId]);

  const handleDeleteMemory = async (id: number) => {
    try {
      const res = await fetch(`http://localhost:8000/memory/${id}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        setMemory(prev => prev.filter(m => m.id !== id));
      }
    } catch (err) {
      console.error("Failed to delete memory rule", err);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center py-20 text-gray-400">
        <Loader className="w-8 h-8 animate-spin" />
      </div>
    );
  }

  // Process data for chart (last 10 scans, chronological order)
  const chartData = [...scans]
    .filter(s => s.status === 'completed' && s.risk_score !== null)
    .slice(0, 10)
    .reverse()
    .map(s => ({
      pr: `PR #${s.pr_number}`,
      score: s.risk_score || 0
    }));

  return (
    <div>
      <Link to="/" className="inline-flex items-center text-sm text-gray-400 hover:text-gray-200 mb-6 transition-colors">
        <ArrowLeft className="w-4 h-4 mr-1" />
        Back to Feed
      </Link>

      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-100 mb-2">
          {repoInfo ? `${repoInfo.owner}/${repoInfo.name}` : `Repo ${repoId}`}
        </h1>
        <p className="text-gray-400">Security history and suppression rules.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Chart & Rules */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Chart */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 shadow-sm">
            <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
              Security Trend
            </h2>
            <div className="h-72 w-full">
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                    <XAxis dataKey="pr" stroke="#9ca3af" tick={{fill: '#9ca3af'}} axisLine={false} tickLine={false} />
                    <YAxis stroke="#9ca3af" domain={[0, 100]} tick={{fill: '#9ca3af'}} axisLine={false} tickLine={false} />
                    <Tooltip 
                      contentStyle={{backgroundColor: '#1f2937', borderColor: '#374151', borderRadius: '0.5rem', color: '#f3f4f6'}}
                      itemStyle={{color: '#10b981'}}
                    />
                    <Line 
                      type="monotone" 
                      dataKey="score" 
                      stroke="#10b981" 
                      strokeWidth={3}
                      dot={{ fill: '#10b981', strokeWidth: 2, r: 4 }}
                      activeDot={{ r: 6 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-gray-500">
                  Not enough data for trend chart
                </div>
              )}
            </div>
          </div>

          {/* Memory Rules */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6 shadow-sm">
            <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              Suppression Rules
            </h2>
            
            {memory.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs text-gray-400 uppercase bg-gray-900/50">
                    <tr>
                      <th className="px-4 py-3 rounded-tl-md">Rule ID</th>
                      <th className="px-4 py-3">File Pattern</th>
                      <th className="px-4 py-3">Outcome</th>
                      <th className="px-4 py-3 text-right rounded-tr-md">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {memory.map((m) => (
                      <tr key={m.id} className="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/20">
                        <td className="px-4 py-3 font-mono text-gray-300">{m.rule_id}</td>
                        <td className="px-4 py-3 text-gray-300 break-all">{m.file_pattern}</td>
                        <td className="px-4 py-3 text-gray-400">
                          <span className="bg-gray-700 px-2 py-1 rounded text-xs">
                            {m.outcome}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button 
                            onClick={() => handleDeleteMemory(m.id)}
                            className="text-gray-500 hover:text-red-400 p-1 transition-colors"
                            title="Delete suppression rule"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500 italic">
                No active suppression rules.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Scan History */}
        <div className="space-y-4">
          <h2 className="text-xl font-semibold mb-4 px-2">Scan History</h2>
          {scans.length > 0 ? (
            scans.map(scan => (
              <div key={scan.id} className="bg-gray-800 rounded-lg border border-gray-700 p-4 shadow-sm hover:border-gray-600 transition-colors">
                <div className="flex justify-between items-start mb-2">
                  <span className="font-medium text-gray-200">PR #{scan.pr_number}</span>
                  <span className={`text-xs px-2 py-1 rounded-full font-medium ${
                    scan.risk_score !== null ? 
                      (scan.risk_score >= 50 ? 'bg-red-500/20 text-red-500' : 
                       scan.risk_score >= 20 ? 'bg-yellow-500/20 text-yellow-500' : 
                       'bg-green-500/20 text-green-500') 
                      : 'bg-gray-700 text-gray-300'
                  }`}>
                    {scan.risk_score !== null ? `Score: ${scan.risk_score}` : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between items-center text-sm mt-3">
                  <span className="text-gray-400 flex items-center gap-1">
                    <span className={`w-2 h-2 rounded-full ${
                      scan.status === 'completed' ? 'bg-green-400' : 
                      scan.status === 'pending' || scan.status === 'running' ? 'bg-yellow-400' : 
                      'bg-red-400'
                    }`}></span>
                    <span className="capitalize">{scan.status}</span>
                  </span>
                  <span className="text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          ) : (
             <div className="text-gray-500 italic px-2">No scans recorded.</div>
          )}
        </div>
      </div>
    </div>
  );
}
