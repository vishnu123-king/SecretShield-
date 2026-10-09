import React from 'react';
import {
  Shield,
  Search,
  LayoutGrid,
  ShieldAlert,
  GitBranch,
  Network,
  Lock,
  FileText,
  Settings,
  LogOut,
  Radio
} from 'lucide-react';
export type ObservatoryTab =
  | 'observatory'
  | 'scan'
  | 'repositories'
  | 'findings'
  | 'exposure'
  | 'prevention'
  | 'reports'
  | 'rules'
  | 'settings';

interface ObservatoryHeaderProps {
  currentTab: ObservatoryTab;
  onTabChange: (tab: ObservatoryTab) => void;
  onLogout: () => void;
  user: any;
  criticalCount: number;
}

export const ObservatoryHeader: React.FC<ObservatoryHeaderProps> = ({
  currentTab,
  onTabChange,
  onLogout,
  user,
  criticalCount
}) => {
  const tabs: Array<{ id: ObservatoryTab; label: string; icon: any }> = [
    { id: 'observatory', label: 'Overview', icon: LayoutGrid },
    { id: 'scan', label: 'Scan', icon: Search },
    { id: 'repositories', label: 'Repositories', icon: GitBranch },
    { id: 'findings', label: 'Findings', icon: ShieldAlert },
    { id: 'exposure', label: 'Exposure', icon: Network },
    { id: 'prevention', label: 'Prevention', icon: Lock },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'rules', label: 'Rules', icon: Shield },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <header className="bg-stone-900 border-b border-stone-800 sticky top-0 z-50">
      <div className="max-w-[1600px] mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-8">
          {/* Logo */}
          <div className="flex items-center space-x-2 cursor-pointer" onClick={() => onTabChange('observatory')}>
            <div className="bg-cyan-600 p-1.5 rounded-lg">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold text-lg tracking-tight text-stone-100 uppercase">SecretShield</span>
          </div>

          {/* Nav */}
          <nav className="hidden lg:flex items-center space-x-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
                  currentTab === tab.id
                    ? 'bg-stone-800 text-cyan-400 border border-stone-700'
                    : 'text-stone-400 hover:text-stone-200 hover:bg-stone-800/50'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
                {tab.id === 'findings' && criticalCount > 0 && (
                  <span className="bg-rose-500 text-white text-[10px] px-1.5 py-0.5 rounded-full animate-pulse">
                    {criticalCount}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        <div className="flex items-center space-x-4">
          <div className="hidden sm:flex items-center space-x-3 pr-4 border-r border-stone-800">
            <div className="flex items-center space-x-2 text-[10px] font-mono text-stone-500">
              <Radio className="w-3 h-3 text-emerald-500 animate-pulse" />
              <span className="uppercase tracking-widest">System Operational</span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-bold text-stone-200">{user.name || 'Security Engineer'}</p>
              <p className="text-[10px] text-stone-500 font-mono">{user.email}</p>
            </div>
            {user.photoURL ? (
              <img src={user.photoURL} alt="User" className="w-8 h-8 rounded-full border border-stone-700" />
            ) : (
              <div className="w-8 h-8 rounded-full bg-stone-800 border border-stone-700 flex items-center justify-center text-xs font-bold text-stone-400">
                {user.name?.[0].toUpperCase() || user.email?.[0].toUpperCase()}
              </div>
            )}
            <button
              onClick={onLogout}
              className="p-2 text-stone-500 hover:text-rose-400 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
