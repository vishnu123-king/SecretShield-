import React from 'react';
import {
  Shield,
  Search,
  Plus,
  Zap,
  Filter,
  ArrowRight,
  Code2,
  Terminal,
  Settings
} from 'lucide-react';

export const RulesObservatory: React.FC = () => {
  const categories = ['Cloud', 'Database', 'Git', 'Payment', 'Authentication', 'Generic'];
  
  const rules = [
    { id: 'aws-access-key', name: 'AWS Access Key ID', severity: 'CRITICAL', confidence: '0.95', type: 'Cloud' },
    { id: 'github-pat', name: 'GitHub Personal Access Token', severity: 'CRITICAL', confidence: '0.98', type: 'Git' },
    { id: 'postgres-url', name: 'PostgreSQL Connection URL', severity: 'HIGH', confidence: '0.90', type: 'Database' },
    { id: 'stripe-key', name: 'Stripe API Key', severity: 'CRITICAL', confidence: '0.95', type: 'Payment' },
    { id: 'jwt-secret', name: 'JWT Secret Assignment', severity: 'MEDIUM', confidence: '0.70', type: 'Authentication' },
    { id: 'generic-secret', name: 'Generic Password/Secret', severity: 'HIGH', confidence: '0.65', type: 'Generic' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-12 animate-in fade-in duration-500">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-stone-800 pb-8">
        <div>
          <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
             <Shield className="w-7 h-7 text-cyan-500" />
             <span>Detection Rules Engine</span>
          </h1>
          <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
            Deterministic YAML signatures & high-entropy heuristics
          </p>
        </div>
        <button
          className="flex items-center space-x-2 px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-cyan-600/20"
        >
          <Plus className="w-4 h-4" />
          <span>Define Custom Rule</span>
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
         {categories.map((cat) => (
            <button key={cat} className="px-4 py-1.5 bg-stone-900 border border-stone-800 rounded-lg text-[10px] font-black uppercase text-stone-400 hover:text-stone-200 transition-colors">
               {cat}
            </button>
         ))}
      </div>

      <div className="bg-stone-900 border border-stone-800 rounded-3xl overflow-hidden shadow-2xl">
         <div className="p-6 border-b border-stone-800 flex items-center justify-between bg-stone-950/30">
            <h3 className="text-[10px] font-black text-stone-500 uppercase tracking-[0.2em]">Active Registry</h3>
            <div className="relative">
               <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-stone-600" />
               <input type="text" placeholder="Search rules..." className="bg-stone-950 border border-stone-800 rounded-lg py-1.5 pl-9 pr-3 text-[10px] text-stone-300 focus:outline-none focus:border-cyan-500 transition-all font-mono" />
            </div>
         </div>
         <div className="divide-y divide-stone-800">
            {rules.map((rule) => (
               <div key={rule.id} className="p-6 flex items-center justify-between hover:bg-stone-800/30 transition-all group">
                  <div className="flex items-center space-x-4">
                     <div className="w-10 h-10 rounded-xl bg-stone-950 border border-stone-800 flex items-center justify-center">
                        <Code2 className="w-5 h-5 text-stone-500 group-hover:text-cyan-400 transition-colors" />
                     </div>
                     <div>
                        <h4 className="text-sm font-bold text-stone-100">{rule.name}</h4>
                        <p className="text-[10px] text-stone-500 font-mono mt-0.5 uppercase tracking-widest">{rule.id} &bull; {rule.type}</p>
                     </div>
                  </div>
                  <div className="flex items-center space-x-12">
                     <div className="text-right">
                        <p className="text-[9px] text-stone-600 uppercase font-black tracking-widest mb-1">Confidence</p>
                        <p className="text-xs font-bold text-stone-300 font-mono">{rule.confidence}</p>
                     </div>
                     <div className="text-right w-24">
                        <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full ${rule.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400' : 'bg-amber-500/10 text-amber-400'}`}>
                           {rule.severity}
                        </span>
                     </div>
                     <button className="p-2 bg-stone-950 border border-stone-800 rounded-xl text-stone-600 hover:text-cyan-400 transition-all">
                        <ArrowRight className="w-4 h-4" />
                     </button>
                  </div>
               </div>
            ))}
         </div>
      </div>

      <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
         <div className="absolute top-0 right-0 p-8 opacity-10">
            <Terminal className="w-32 h-32 text-cyan-500" />
         </div>
         <div className="space-y-6 relative z-10">
            <h3 className="text-xs font-black text-stone-500 uppercase tracking-widest flex items-center space-x-2">
               <Zap className="w-4 h-4 text-amber-500" />
               <span>Sandbox Rule Tester</span>
            </h3>
            <p className="text-sm text-stone-200 font-bold">Paste a candidate string below to verify detection patterns.</p>
            <div className="bg-stone-950 border border-stone-800 rounded-2xl p-4 font-mono text-xs text-stone-400 min-h-[100px] shadow-inner flex items-center justify-center italic">
               Waiting for input...
            </div>
            <button className="px-6 py-2.5 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-[10px] font-black uppercase tracking-widest border border-stone-700 transition-all">
               Run Simulation
            </button>
         </div>
      </div>
    </div>
  );
};
