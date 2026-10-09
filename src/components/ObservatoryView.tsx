import React from 'react';
import {
  Compass,
  Radio,
  Flame,
  History,
  ShieldAlert,
  GitBranch,
  ArrowRight,
  Shield,
  Zap,
  LayoutGrid
} from 'lucide-react';
import { DashboardMetrics, ScanRecord, Finding, Repository } from '../types';

interface ObservatoryViewProps {
  metrics: DashboardMetrics | null;
  secretsByType: Array<{ name: string; count: number }>;
  repositories: Repository[];
  recentScans: ScanRecord[];
  recentFindings: Finding[];
  onNavigateTab: (tab: any) => void;
  isLoading: boolean;
}

export const ObservatoryView: React.FC<ObservatoryViewProps> = ({
  metrics,
  secretsByType,
  repositories,
  recentScans,
  recentFindings,
  onNavigateTab,
  isLoading
}) => {
  if (isLoading || !metrics) {
    return (
      <div className="py-24 flex flex-col items-center justify-center space-y-4">
        <Radio className="w-8 h-8 text-cyan-500 animate-spin" />
        <span className="text-stone-500 font-mono text-xs uppercase tracking-widest">Gathering intelligence...</span>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8 animate-in fade-in duration-500">
      {/* Hero Header */}
      <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 flex flex-col md:flex-row items-center justify-between gap-8 relative overflow-hidden shadow-2xl">
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 blur-[120px] rounded-full"></div>
        <div className="absolute bottom-0 left-0 w-64 h-64 bg-rose-500/5 blur-[120px] rounded-full"></div>
        
        <div className="space-y-4 relative z-10 text-center md:text-left">
          <div className="inline-flex items-center space-x-2 px-3 py-1 bg-cyan-950/30 border border-cyan-800/50 rounded-full text-[10px] font-bold text-cyan-400 uppercase tracking-widest">
            <Compass className="w-3 h-3" />
            <span>Security Observatory Active</span>
          </div>
          <h1 className="text-3xl lg:text-4xl font-extrabold text-stone-100 tracking-tight">
            Repository Intelligence Deck
          </h1>
          <p className="text-stone-400 text-sm max-w-xl leading-relaxed">
            Continuously analyzing active source files and traversing deep Git history to identify exposed credentials across {metrics.total_repositories} repositories.
          </p>
          <div className="flex flex-wrap justify-center md:justify-start gap-4">
            <button
              onClick={() => onNavigateTab('scan')}
              className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-cyan-600/20"
            >
              Scan New Repository
            </button>
            <button
              onClick={() => onNavigateTab('findings')}
              className="px-6 py-2.5 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-xs font-bold border border-stone-700 transition-all"
            >
              Investigate Findings
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 relative z-10">
          <div className="bg-stone-950/50 border border-stone-800 rounded-2xl p-4 w-32 md:w-40 text-center">
            <span className="text-[10px] text-stone-500 uppercase font-bold tracking-wider">Scans Run</span>
            <p className="text-2xl font-black text-stone-100 mt-1">{metrics.total_scans}</p>
          </div>
          <div className="bg-rose-950/20 border border-rose-900/30 rounded-2xl p-4 w-32 md:w-40 text-center">
            <span className="text-[10px] text-rose-500 uppercase font-bold tracking-wider">Critical</span>
            <p className="text-2xl font-black text-rose-400 mt-1">{metrics.critical_count}</p>
          </div>
          <div className="bg-stone-950/50 border border-stone-800 rounded-2xl p-4 w-32 md:w-40 text-center">
            <span className="text-[10px] text-stone-500 uppercase font-bold tracking-wider">Clean</span>
            <p className="text-2xl font-black text-emerald-400 mt-1">{metrics.resolved_findings}</p>
          </div>
          <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-2xl p-4 w-32 md:w-40 text-center">
            <span className="text-[10px] text-cyan-500 uppercase font-bold tracking-wider">Risk Index</span>
            <p className="text-2xl font-black text-cyan-400 mt-1">{metrics.overall_risk_index}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Exposure Intelligence Split */}
        <div className="lg:col-span-8 space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-black text-stone-500 uppercase tracking-[0.2em] flex items-center space-x-2">
              <Radio className="w-3 h-3 text-cyan-500" />
              <span>Active Exposure Stream</span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-stone-900 border border-rose-900/30 rounded-2xl p-5 flex flex-col justify-between space-y-4">
              <div className="flex items-center justify-between">
                <div className="p-2 bg-rose-500/10 rounded-lg">
                  <Flame className="w-5 h-5 text-rose-500" />
                </div>
                <span className="text-[10px] font-mono font-bold text-rose-500">P0 PRIORITY</span>
              </div>
              <div>
                <h3 className="text-base font-bold text-stone-100">Live Credentials</h3>
                <p className="text-xs text-stone-400 mt-1">Exposed in current working files (HEAD)</p>
              </div>
              <div className="flex items-end justify-between">
                <span className="text-3xl font-black text-stone-100">{metrics.currently_exposed}</span>
                <button onClick={() => onNavigateTab('findings')} className="text-xs font-bold text-rose-400 hover:underline">Fix now &rarr;</button>
              </div>
            </div>

            <div className="bg-stone-900 border border-cyan-900/30 rounded-2xl p-5 flex flex-col justify-between space-y-4">
              <div className="flex items-center justify-between">
                <div className="p-2 bg-cyan-500/10 rounded-lg">
                  <History className="w-5 h-5 text-cyan-500" />
                </div>
                <span className="text-[10px] font-mono font-bold text-cyan-500">RESIDUAL RISK</span>
              </div>
              <div>
                <h3 className="text-base font-bold text-stone-100">Historical Leaks</h3>
                <p className="text-xs text-stone-400 mt-1">Deleted from files but persist in Git history</p>
              </div>
              <div className="flex items-end justify-between">
                <span className="text-3xl font-black text-stone-100">{metrics.historical_only}</span>
                <button onClick={() => onNavigateTab('exposure')} className="text-xs font-bold text-cyan-400 hover:underline">Purge history &rarr;</button>
              </div>
            </div>
          </div>

          <div className="bg-stone-900 border border-stone-800 rounded-2xl overflow-hidden">
            <div className="p-4 border-b border-stone-800 flex items-center justify-between">
              <h3 className="text-[10px] font-bold text-stone-400 uppercase tracking-widest">Recent Findings</h3>
              <button onClick={() => onNavigateTab('findings')} className="text-[10px] font-bold text-cyan-500 hover:text-cyan-400 uppercase tracking-widest">View All</button>
            </div>
            <div className="divide-y divide-stone-800">
              {recentFindings.length === 0 ? (
                <div className="py-12 text-center text-stone-500 text-xs font-mono">No findings detected yet.</div>
              ) : (
                recentFindings.map((f) => (
                  <div key={f.id} className="p-4 flex items-center justify-between hover:bg-stone-800/30 transition-colors">
                    <div className="flex items-center space-x-4 min-w-0">
                      <div className={`p-1.5 rounded-lg ${f.severity === 'CRITICAL' ? 'bg-rose-500/10' : 'bg-amber-500/10'}`}>
                        <ShieldAlert className={`w-4 h-4 ${f.severity === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'}`} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-bold text-stone-200 truncate">{f.rule_name}</p>
                        <p className="text-[10px] text-stone-500 font-mono truncate">{f.repository_name} &bull; {f.primary_file}</p>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${f.status === 'Open' ? 'bg-rose-950/30 text-rose-400 border border-rose-900/30' : 'bg-stone-800 text-stone-400'}`}>
                        {f.status}
                      </span>
                      <p className="text-[9px] text-stone-600 mt-1 font-mono uppercase">{new Date(f.first_seen || '').toLocaleDateString()}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Sidebar */}
        <div className="lg:col-span-4 space-y-8">
           <div className="space-y-6">
            <h2 className="text-xs font-black text-stone-500 uppercase tracking-[0.2em] flex items-center space-x-2">
              <Zap className="w-3 h-3 text-amber-500" />
              <span>Secret Distribution</span>
            </h2>
            <div className="bg-stone-900 border border-stone-800 rounded-2xl p-6 space-y-4">
              {secretsByType.map((s, i) => (
                <div key={i} className="space-y-2">
                  <div className="flex justify-between text-xs">
                    <span className="text-stone-300">{s.name}</span>
                    <span className="text-stone-100 font-bold">{s.count}</span>
                  </div>
                  <div className="h-1.5 w-full bg-stone-950 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-cyan-600 rounded-full" 
                      style={{ width: `${Math.min(100, (s.count / metrics.total_findings) * 100)}%` }}
                    ></div>
                  </div>
                </div>
              ))}
              {secretsByType.length === 0 && (
                <p className="text-stone-500 text-xs font-mono py-4 text-center">No classified data yet.</p>
              )}
            </div>
          </div>

          <div className="space-y-6">
            <h2 className="text-xs font-black text-stone-500 uppercase tracking-[0.2em] flex items-center space-x-2">
              <GitBranch className="w-3 h-3 text-emerald-500" />
              <span>High Risk Repositories</span>
            </h2>
            <div className="space-y-3">
              {repositories.slice(0, 3).map((r) => (
                <div key={r.id} className="bg-stone-900 border border-stone-800 p-4 rounded-2xl flex items-center justify-between group cursor-pointer hover:border-stone-600 transition-colors">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 rounded-lg bg-stone-950 border border-stone-800 flex items-center justify-center">
                      <LayoutGrid className="w-4 h-4 text-stone-400 group-hover:text-cyan-400 transition-colors" />
                    </div>
                    <div>
                      <p className="text-xs font-bold text-stone-200">{r.name}</p>
                      <p className="text-[10px] text-stone-500 font-mono">{r.risk_index} / 100 RISK</p>
                    </div>
                  </div>
                  <ArrowRight className="w-4 h-4 text-stone-700 group-hover:text-stone-400 transition-colors" />
                </div>
              ))}
              {repositories.length === 0 && (
                 <p className="text-stone-500 text-xs font-mono py-4 text-center">No repositories scanned.</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
