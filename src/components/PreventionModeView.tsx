import React from 'react';
import {
  ShieldCheck,
  Zap,
  Terminal,
  FileCode2,
  Lock,
  ChevronRight,
  GitCompare,
  ArrowRight,
  Settings
} from 'lucide-react';
import { PolicyConfig } from '../types';

interface PreventionModeViewProps {
  policy: PolicyConfig | null;
}

export const PreventionModeView: React.FC<PreventionModeViewProps> = ({ policy }) => {
  const steps = [
    { 
      title: 'Local Pre-commit Hook', 
      desc: 'Block secrets before they leave your workstation. Install our deterministic scanner as a Git hook.',
      cmd: 'secretshield install-hook',
      status: policy?.precommit_enforced ? 'active' : 'available'
    },
    { 
      title: 'Pull Request Gate', 
      desc: 'Fail CI/CD pipelines if critical credentials are found in incoming diffs.',
      cmd: 'secretshield diff --format json',
      status: policy?.pr_checks_enforced ? 'active' : 'available'
    },
    { 
      title: 'Environment Scanning', 
      desc: 'Monitor production environments for runtime secret leakage in configuration logs.',
      cmd: 'secretshield scan /etc/app/config',
      status: 'upcoming'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-12 animate-in fade-in duration-500">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-stone-800 pb-8">
        <div>
          <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
             <ShieldCheck className="w-7 h-7 text-emerald-500" />
             <span>Prevention Mode</span>
          </h1>
          <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
            Defensive controls & proactive security gates
          </p>
        </div>
        <div className="flex items-center space-x-2 px-4 py-1.5 bg-emerald-950/20 border border-emerald-800/50 rounded-full">
           <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
           <span className="text-[10px] font-black text-emerald-500 uppercase tracking-widest">Shield Active</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {steps.map((step, i) => (
          <div key={i} className="bg-stone-900 border border-stone-800 rounded-3xl p-8 space-y-6 shadow-xl relative overflow-hidden flex flex-col group hover:border-stone-700 transition-all">
             <div className="space-y-4">
                <div className="flex items-center justify-between">
                   <div className="p-3 bg-stone-950 rounded-2xl border border-stone-800">
                      <Zap className={`w-5 h-5 ${step.status === 'active' ? 'text-emerald-500' : 'text-stone-500'}`} />
                   </div>
                   <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-full ${step.status === 'active' ? 'bg-emerald-500 text-white' : 'bg-stone-800 text-stone-500'}`}>
                     {step.status}
                   </span>
                </div>
                <h3 className="text-lg font-bold text-stone-100">{step.title}</h3>
                <p className="text-xs text-stone-400 leading-relaxed font-mono italic">"{step.desc}"</p>
             </div>

             <div className="flex-1"></div>

             <div className="space-y-3">
                <div className="bg-stone-950 border border-stone-800 rounded-xl p-3 flex items-center justify-between group/cmd cursor-pointer hover:border-cyan-500/30 transition-colors">
                   <code className="text-[10px] text-cyan-400 font-mono">{step.cmd}</code>
                   <Terminal className="w-3 h-3 text-stone-700 group-hover/cmd:text-cyan-500 transition-colors" />
                </div>
                <button className="w-full py-2 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-[10px] font-black uppercase tracking-widest border border-stone-700 transition-all">
                   Setup Protocol &rarr;
                </button>
             </div>
          </div>
        ))}
      </div>

      <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 shadow-2xl space-y-8">
         <div className="flex items-center space-x-3">
            <Settings className="w-5 h-5 text-stone-500" />
            <h2 className="text-sm font-black text-stone-100 uppercase tracking-widest">Enforcement Policies</h2>
         </div>

         <div className="grid grid-cols-1 md:grid-cols-2 gap-12">
            <div className="space-y-6">
               <div className="space-y-2 border-l-2 border-rose-500/50 pl-4">
                  <p className="text-xs font-bold text-stone-200">Critical Thresholds</p>
                  <p className="text-[10px] text-stone-500 uppercase tracking-wider font-mono">Status: <span className="text-rose-400 font-bold">Hard Block</span></p>
                  <p className="text-[10px] text-stone-600 leading-relaxed">AWS, GitHub, Stripe, and Private Keys are automatically rejected during diff scans and pre-commit checks.</p>
               </div>
               <div className="space-y-2 border-l-2 border-amber-500/50 pl-4">
                  <p className="text-xs font-bold text-stone-200">High Risk Thresholds</p>
                  <p className="text-[10px] text-stone-500 uppercase tracking-wider font-mono">Status: <span className="text-amber-400 font-bold">Block</span></p>
                  <p className="text-[10px] text-stone-600 leading-relaxed">Database connection strings and Generic Secret assignments are blocked unless explicitly suppressed.</p>
               </div>
            </div>

            <div className="space-y-8">
               <div className="p-6 bg-stone-950/50 border border-stone-800 rounded-2xl space-y-4">
                  <div className="flex items-center justify-between">
                     <span className="text-[10px] font-black text-stone-500 uppercase tracking-widest">Risk Enforcement</span>
                     <span className="text-xs font-bold text-cyan-400 font-mono">{policy?.max_allowed_risk_score || 50} / 100</span>
                  </div>
                  <div className="h-2 w-full bg-stone-900 rounded-full overflow-hidden">
                     <div className="h-full bg-cyan-600 rounded-full" style={{ width: `${policy?.max_allowed_risk_score || 50}%` }}></div>
                  </div>
                  <p className="text-[10px] text-stone-600 font-mono italic">Commits with a calculated risk index higher than this value will be rejected.</p>
               </div>
               
               <button className="w-full py-4 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-2xl font-black text-xs uppercase tracking-[0.2em] border border-stone-700 transition-all shadow-xl">
                  Configure Global Policy
               </button>
            </div>
         </div>
      </div>
    </div>
  );
};
