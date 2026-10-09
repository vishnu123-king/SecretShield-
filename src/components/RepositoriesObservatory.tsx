import React from 'react';
import {
  GitBranch,
  Search,
  Plus,
  Play,
  Trash2,
  FileText,
  Clock,
  ExternalLink,
  Flame,
  History,
  ShieldCheck,
  FolderGit2,
  ChevronRight
} from 'lucide-react';
import { Repository } from '../types';

interface RepositoriesObservatoryProps {
  repositories: Repository[];
  onNavigateScan: (url?: string) => void;
  onNavigateHistory: (repoId: number) => void;
}

export const RepositoriesObservatory: React.FC<RepositoriesObservatoryProps> = ({
  repositories,
  onNavigateScan,
  onNavigateHistory
}) => {
  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-stone-800 pb-8">
        <div>
          <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
             <FolderGit2 className="w-7 h-7 text-cyan-500" />
             <span>Repository Security Profiles</span>
          </h1>
          <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
            Monitored code assets &bull; {repositories.length} total entries
          </p>
        </div>
        <button
          onClick={() => onNavigateScan()}
          className="flex items-center space-x-2 px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-cyan-600/20"
        >
          <Plus className="w-4 h-4" />
          <span>Onboard Repository</span>
        </button>
      </div>

      {repositories.length === 0 ? (
        <div className="py-32 flex flex-col items-center justify-center space-y-6 text-stone-800">
          <div className="p-12 bg-stone-900 rounded-full border border-stone-800">
            <GitBranch className="w-16 h-16" />
          </div>
          <div className="text-center space-y-2">
            <p className="text-lg font-black uppercase tracking-widest">No Code Assets</p>
            <p className="text-xs font-mono">Onboard your first repository to begin surveillance.</p>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {repositories.map((repo) => (
            <div key={repo.id} className="bg-stone-900 border border-stone-800 rounded-3xl p-6 space-y-6 hover:border-stone-700 transition-all group flex flex-col shadow-xl">
              <div className="flex items-start justify-between">
                <div className="space-y-1 min-w-0">
                  <h3 className="text-lg font-bold text-stone-100 truncate group-hover:text-cyan-400 transition-colors">
                    {repo.name}
                  </h3>
                  <p className="text-[10px] text-stone-500 font-mono truncate uppercase">
                    {repo.source} &bull; {repo.default_branch}
                  </p>
                </div>
                <div className={`p-2 rounded-xl ${repo.risk_index > 50 ? 'bg-rose-500/10 text-rose-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
                   {repo.risk_index > 50 ? <Flame className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-stone-950/50 rounded-2xl p-3 border border-stone-800/50">
                   <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Findings</p>
                   <p className="text-xl font-black text-stone-200 mt-1">{repo.total_findings}</p>
                </div>
                <div className="bg-stone-950/50 rounded-2xl p-3 border border-stone-800/50">
                   <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Risk Score</p>
                   <p className="text-xl font-black text-stone-200 mt-1">{repo.risk_index}</p>
                </div>
              </div>

              <div className="space-y-3 pt-2 border-t border-stone-800/50">
                 <div className="flex items-center justify-between text-[10px] font-mono text-stone-500">
                    <span className="flex items-center space-x-1">
                      <Clock className="w-3 h-3" />
                      <span>Last Scanned:</span>
                    </span>
                    <span className="text-stone-300 uppercase">
                      {repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleDateString() : 'Never'}
                    </span>
                 </div>
                 <div className="flex items-center justify-between text-[10px] font-mono text-stone-500">
                    <span className="flex items-center space-x-1">
                      <History className="w-3 h-3" />
                      <span>Status:</span>
                    </span>
                    <span className={`font-bold ${repo.status === 'scanning' ? 'text-cyan-400 animate-pulse' : 'text-stone-300 uppercase'}`}>
                      {repo.status}
                    </span>
                 </div>
              </div>

              <div className="flex-1"></div>

              <div className="flex items-center space-x-2 pt-4">
                <button
                  onClick={() => onNavigateScan(repo.url)}
                  className="flex-1 bg-stone-800 hover:bg-stone-700 text-stone-200 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border border-stone-700 transition-all flex items-center justify-center space-x-2"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Rescan</span>
                </button>
                <button
                  onClick={() => onNavigateHistory(repo.id)}
                   className="p-2 bg-stone-950 border border-stone-800 rounded-xl text-stone-500 hover:text-cyan-400 transition-all"
                   title="View History"
                >
                  <FileText className="w-4 h-4" />
                </button>
                <a
                  href={repo.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2 bg-stone-950 border border-stone-800 rounded-xl text-stone-500 hover:text-stone-300 transition-all"
                  title="Open Source"
                >
                  <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
