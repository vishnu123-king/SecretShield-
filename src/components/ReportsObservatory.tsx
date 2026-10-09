import React from 'react';
import {
  FileText,
  Download,
  CheckCircle2,
  ShieldAlert,
  ArrowRight,
  ExternalLink,
  History,
  TrendingUp,
  LayoutGrid,
  GitBranch
} from 'lucide-react';
import { Repository } from '../types';

interface ReportsObservatoryProps {
  repositories: Repository[];
}

export const ReportsObservatory: React.FC<ReportsObservatoryProps> = ({ repositories }) => {
  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-12 animate-in fade-in duration-500">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-stone-800 pb-8">
        <div>
          <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
             <FileText className="w-7 h-7 text-cyan-500" />
             <span>Security Assessment Reports</span>
          </h1>
          <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
            Compliance documentation & executive summaries
          </p>
        </div>
        <button
          className="flex items-center space-x-2 px-6 py-2.5 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-xs font-bold border border-stone-700 transition-all shadow-lg"
        >
          <History className="w-4 h-4" />
          <span>Report Archive</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
         <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 space-y-6 shadow-xl flex flex-col group hover:border-stone-700 transition-all">
            <div className="space-y-2">
               <div className="p-3 bg-stone-950 rounded-2xl border border-stone-800 w-fit">
                  <TrendingUp className="w-6 h-6 text-cyan-500" />
               </div>
               <h3 className="text-xl font-bold text-stone-100 pt-2">Global Executive Summary</h3>
               <p className="text-xs text-stone-400 leading-relaxed font-mono italic">"Aggregated security posture across all onboarded code assets and organizations."</p>
            </div>
            <div className="flex-1"></div>
            <div className="grid grid-cols-3 gap-4 border-t border-stone-800 pt-6">
               <button className="flex flex-col items-center space-y-2 group/btn">
                  <div className="p-3 bg-stone-950 rounded-xl border border-stone-800 group-hover/btn:border-cyan-500/50 transition-colors">
                     <Download className="w-4 h-4 text-stone-500 group-hover/btn:text-cyan-400" />
                  </div>
                  <span className="text-[10px] font-black uppercase text-stone-600">PDF</span>
               </button>
               <button className="flex flex-col items-center space-y-2 group/btn">
                  <div className="p-3 bg-stone-950 rounded-xl border border-stone-800 group-hover/btn:border-cyan-500/50 transition-colors">
                     <LayoutGrid className="w-4 h-4 text-stone-500 group-hover/btn:text-cyan-400" />
                  </div>
                  <span className="text-[10px] font-black uppercase text-stone-600">CSV</span>
               </button>
               <button className="flex flex-col items-center space-y-2 group/btn">
                  <div className="p-3 bg-stone-950 rounded-xl border border-stone-800 group-hover/btn:border-cyan-500/50 transition-colors">
                     <ExternalLink className="w-4 h-4 text-stone-500 group-hover/btn:text-cyan-400" />
                  </div>
                  <span className="text-[10px] font-black uppercase text-stone-600">HTML</span>
               </button>
            </div>
         </div>

         <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 space-y-6 shadow-xl flex flex-col group hover:border-stone-700 transition-all border-dashed">
            <div className="space-y-2">
               <div className="p-3 bg-stone-950 rounded-2xl border border-stone-800 w-fit">
                  <CheckCircle2 className="w-6 h-6 text-emerald-500" />
               </div>
               <h3 className="text-xl font-bold text-stone-100 pt-2">Compliance Attestation</h3>
               <p className="text-xs text-stone-400 leading-relaxed font-mono italic">"Generate evidence for SOC2, HIPAA, or ISO 27001 audits based on finding resolutions."</p>
            </div>
            <div className="flex-1"></div>
            <button className="w-full py-3 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] border border-stone-700 transition-all">
               Generate Compliance Evidence
            </button>
         </div>
      </div>

      <div className="space-y-6">
         <h2 className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1 flex items-center space-x-2">
            <ShieldAlert className="w-3 h-3" />
            <span>Repository Deep Dives</span>
         </h2>
         <div className="bg-stone-900 border border-stone-800 rounded-3xl overflow-hidden shadow-2xl">
            <table className="w-full text-left border-collapse">
               <thead>
                  <tr className="bg-stone-950/50 border-b border-stone-800">
                     <th className="px-6 py-4 text-[10px] font-black text-stone-500 uppercase tracking-widest">Code Asset</th>
                     <th className="px-6 py-4 text-[10px] font-black text-stone-500 uppercase tracking-widest">Last Audit</th>
                     <th className="px-6 py-4 text-[10px] font-black text-stone-500 uppercase tracking-widest text-center">Status</th>
                     <th className="px-6 py-4 text-[10px] font-black text-stone-500 uppercase tracking-widest text-right">Actions</th>
                  </tr>
               </thead>
               <tbody className="divide-y divide-stone-800">
                  {repositories.map((repo) => (
                     <tr key={repo.id} className="hover:bg-stone-800/30 transition-colors group">
                        <td className="px-6 py-4">
                           <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 rounded-lg bg-stone-950 border border-stone-800 flex items-center justify-center">
                                 <GitBranch className="w-4 h-4 text-stone-400 group-hover:text-cyan-400 transition-colors" />
                              </div>
                              <span className="text-xs font-bold text-stone-200">{repo.name}</span>
                           </div>
                        </td>
                        <td className="px-6 py-4">
                           <span className="text-[10px] text-stone-500 font-mono uppercase">{repo.last_scanned_at ? new Date(repo.last_scanned_at).toLocaleDateString() : 'Never'}</span>
                        </td>
                        <td className="px-6 py-4 text-center">
                           <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full ${repo.risk_index > 0 ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                              {repo.risk_index > 0 ? 'Exposed' : 'Secure'}
                           </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                           <button className="p-2 text-stone-500 hover:text-cyan-400 transition-colors">
                              <Download className="w-4 h-4" />
                           </button>
                        </td>
                     </tr>
                  ))}
                  {repositories.length === 0 && (
                     <tr>
                        <td colSpan={4} className="px-6 py-12 text-center text-stone-700 text-xs font-mono italic">No data available for reporting.</td>
                     </tr>
                  )}
               </tbody>
            </table>
         </div>
      </div>
    </div>
  );
};
