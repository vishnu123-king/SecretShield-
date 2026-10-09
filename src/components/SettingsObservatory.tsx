import React from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  User,
  Users,
  Database,
  Lock,
  Bell,
  Globe,
  ChevronRight,
  Code2
} from 'lucide-react';

export const SettingsObservatory: React.FC = () => {
  const sections = [
    { title: 'Account Profile', icon: User, desc: 'Manage your personal identity and auth credentials.' },
    { title: 'Organization', icon: Users, desc: 'Configure team access, RBAC, and billing structures.' },
    { title: 'Repository Access', icon: Database, desc: 'Store Personal Access Tokens (PAT) and SSH keys safely.' },
    { title: 'Scan Defaults', icon: Code2, desc: 'Set global exclusions, file limits, and history depth.' },
    { title: 'Security & Policy', icon: Shield, desc: 'Define enforcement thresholds and block rules.' },
    { title: 'Integrations', icon: Globe, desc: 'Connect to Slack, Microsoft Teams, or Webhooks.' },
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-12 animate-in fade-in duration-500">
      <div className="border-b border-stone-800 pb-8">
        <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
          <SettingsIcon className="w-7 h-7 text-stone-500" />
          <span>Platform Configuration</span>
        </h1>
        <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
           System governance & individual preferences
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {sections.map((section, i) => (
          <div key={i} className="bg-stone-900 border border-stone-800 rounded-3xl p-6 hover:border-stone-700 transition-all cursor-pointer group shadow-xl flex flex-col space-y-4">
             <div className="p-3 bg-stone-950 rounded-2xl border border-stone-800 w-fit group-hover:border-cyan-500/30 transition-colors">
                <section.icon className="w-5 h-5 text-stone-500 group-hover:text-cyan-500 transition-colors" />
             </div>
             <div className="space-y-1">
                <h3 className="text-sm font-bold text-stone-200 group-hover:text-stone-100 transition-colors">{section.title}</h3>
                <p className="text-[10px] text-stone-500 font-mono leading-relaxed italic group-hover:text-stone-400">"{section.desc}"</p>
             </div>
             <div className="flex-1"></div>
             <div className="flex items-center justify-between pt-2 border-t border-stone-800/50">
                <span className="text-[9px] font-black uppercase text-stone-600 tracking-widest group-hover:text-stone-400 transition-colors">Configure Section</span>
                <ChevronRight className="w-3 h-3 text-stone-700 group-hover:text-stone-400 transition-transform group-hover:translate-x-1" />
             </div>
          </div>
        ))}
      </div>

      <div className="bg-rose-950/10 border border-rose-900/30 rounded-3xl p-8 space-y-6 shadow-2xl relative overflow-hidden">
         <div className="absolute top-0 right-0 p-8 opacity-20">
            <Shield className="w-32 h-32 text-rose-500" />
         </div>
         <div className="space-y-4 relative z-10">
            <h3 className="text-xs font-black text-rose-400 uppercase tracking-widest flex items-center space-x-2">
               <Lock className="w-4 h-4" />
               <span>Hardened Vault Protocol</span>
            </h3>
            <p className="text-sm text-stone-200 font-bold max-w-2xl leading-relaxed">
               All infrastructure-level credentials and repository access tokens are encrypted using AES-256 before being stored in our hardware-backed security modules.
            </p>
            <button className="px-6 py-2.5 bg-rose-900/50 hover:bg-rose-900 text-rose-100 rounded-xl text-[10px] font-black uppercase tracking-widest border border-rose-800/50 transition-all">
               Rotate Master Key
            </button>
         </div>
      </div>
    </div>
  );
};
