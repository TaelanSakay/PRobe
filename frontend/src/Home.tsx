import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, CheckCircle, AlertTriangle, AlertCircle, Loader } from 'lucide-react';
import { Scan, Finding } from './types';

const getBadge = (score: number | null) => {
  if (score === null) return { color: 'bg-gray-700', text: 'N/A' };
  if (score >= 50) return { color: 'bg-red-500/20 text-red-500', text: `High (${score})`, icon: <AlertCircle className="w-4 h-4" /> };
  if (score >= 20) return { color: 'bg-yellow-500/20 text-yellow-500', text: `Med (${score})`, icon: <AlertTriangle className="w-4 h-4" /> };
  return { color: 'bg-green-500/20 text-green-500', text: `Low (${score})`, icon: <CheckCircle className="w-4 h-4" /> };
};

const ScanRow = ({ scan }: { scan: Scan }) => {
  const [expanded, setExpanded] = useState(false);
  const badge = getBadge(scan.risk_score);

  return (
    <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden mb-4 transition-all hover:border-gray-600">
      <div 
        className="p-4 flex items-center justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4 flex-1">
          <button className="text-gray-400 hover:text-gray-200 focus:outline-none">
            {expanded ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
          </button>
          
          <div className="flex flex-col">
            <Link 
              to={`/repo/${scan.repo_id}`}
              className="font-semibold text-lg hover:text-green-400 transition-colors"
              onClick={(e) => e.stopPropagation()}
            >
              {scan.owner}/{scan.repo_name}
            </Link>
            <span className="text-sm text-gray-400">PR #{scan.pr_number} • {new Date(scan.created_at).toLocaleString()}</span>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="text-sm">
            <span className="text-gray-400 mr-2">Findings:</span>
            <span className="font-mono text-gray-200">{scan.finding_count}</span>
          </div>
          <div className="text-sm">
            <span className="text-gray-400 mr-2">Status:</span>
            <span className={`capitalize ${scan.status === 'completed' ? 'text-green-400' : scan.status === 'pending' || scan.status === 'running' ? 'text-yellow-400' : 'text-red-400'}`}>
              {scan.status}
            </span>
          </div>
          <div className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium ${badge.color}`}>
            {badge.icon}
            {badge.text}
          </div>
        </div>
      </div>

      {expanded && (
        <div className="bg-gray-800/50 p-4 border-t border-gray-700">
          {scan.findings.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-gray-400 uppercase bg-gray-900/50">
                  <tr>
                    <th className="px-4 py-3 rounded-tl-md">Severity</th>
                    <th className="px-4 py-3">Rule ID</th>
                    <th className="px-4 py-3">File</th>
                    <th className="px-4 py-3 rounded-tr-md">Line</th>
                  </tr>
                </thead>
                <tbody>
                  {scan.findings.map((f, i) => (
                    <tr key={i} className="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/20">
                      <td className="px-4 py-3">
                        <span className={`capitalize ${f.severity === 'high' ? 'text-red-400' : f.severity === 'medium' ? 'text-yellow-400' : 'text-green-400'}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-gray-300">{f.rule_id}</td>
                      <td className="px-4 py-3 text-gray-300 break-all">{f.file_path}</td>
                      <td className="px-4 py-3 text-gray-400 font-mono">{f.line_number}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-6 text-gray-400 italic">
              No vulnerabilities found! 🎉
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default function Home() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('http://localhost:8000/scans')
      .then(res => res.json())
      .then(data => {
        setScans(data.scans || []);
        setLoading(false);
      })
      .catch(err => {
        console.error("Failed to fetch scans:", err);
        setLoading(false);
      });
  }, []);

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100 mb-2">Recent Scans</h1>
          <p className="text-gray-400">Security feed across all monitored repositories.</p>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center items-center py-20 text-gray-400">
          <Loader className="w-8 h-8 animate-spin" />
        </div>
      ) : scans.length === 0 ? (
        <div className="text-center py-20 bg-gray-800 rounded-lg border border-gray-700">
          <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-medium text-gray-300">No scans yet</h2>
          <p className="text-gray-500 mt-2">Install the GitHub app and open a PR to get started.</p>
        </div>
      ) : (
        <div className="flex flex-col">
          {scans.map(scan => (
            <ScanRow key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}
