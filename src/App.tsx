import React, { useState, useEffect } from 'react';
import { api, setAuthToken } from './services/api';
import { ObservatoryHeader, ObservatoryTab } from './components/ObservatoryHeader';
import { ObservatoryView } from './components/ObservatoryView';
import { ScanRepositoryView } from './components/ScanRepositoryView';
import { FindingsExplorer } from './components/FindingsExplorer';
import { RepositoriesObservatory } from './components/RepositoriesObservatory';
import { ExposureIntelligenceView } from './components/ExposureIntelligenceView';
import { PreventionModeView } from './components/PreventionModeView';
import { ReportsObservatory } from './components/ReportsObservatory';
import { RulesObservatory } from './components/RulesObservatory';
import { SettingsObservatory } from './components/SettingsObservatory';
import { Shield, Lock, Radio, User as UserIcon, Mail, Key } from 'lucide-react';

import {
  Repository,
  ScanRecord,
  Finding,
  AuditLog,
  DashboardMetrics,
  PolicyConfig
} from './types';

export function App() {
  const [user, setUser] = useState<any>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [currentTab, setCurrentTab] = useState<ObservatoryTab>('observatory');
  const [isLoading, setIsLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  
  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [error, setError] = useState('');

  // Data State
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [secretsByType, setSecretsByType] = useState<Array<{ name: string; count: number }>>([]);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [securityPolicy, setSecurityPolicy] = useState<PolicyConfig | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [scanInitialUrl, setScanInitialUrl] = useState('');

  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem('ss_token');
      if (token) {
        setAuthToken(token);
        try {
          const data = await api.getMe();
          setUser(data.user);
          loadAllData();
        } catch (e) {
          console.error('Session invalid', e);
          handleLogout();
        }
      }
      setAuthLoading(false);
    };
    initAuth();
  }, []);

  const loadAllData = async () => {
    setIsLoading(true);
    try {
      const data = await api.getOverview();
      setMetrics(data.metrics);
      setSecretsByType(data.secrets_by_type);
      setRepositories(data.repositories);
      setScans(data.recent_scans);
      setFindings(data.recent_findings);
      setSecurityPolicy(data.security_policy);
    } catch (e) {
      console.error('Failed to load data', e);
      if (e instanceof Error && e.message.includes('Unauthorized')) {
        handleLogout();
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const data = await api.login({ email, password });
      setUser(data.user);
      loadAllData();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const data = await api.register({ email, password, name });
      setUser(data.user);
      loadAllData();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickDemoLogin = async () => {
    setError('');
    setIsLoading(true);
    try {
      let data;
      try {
        data = await api.login({ email: 'demo@secretshield.io', password: 'Password123!' });
      } catch {
        data = await api.register({ email: 'demo@secretshield.io', password: 'Password123!', name: 'Security Analyst' });
      }
      setUser(data.user);
      loadAllData();
    } catch (e: any) {
      setError(e.message || 'Demo login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    api.logout();
    setUser(null);
  };

  if (authLoading) {
    return (
      <div className="min-h-screen bg-stone-950 flex items-center justify-center">
        <Radio className="w-8 h-8 text-cyan-500 animate-spin" />
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-stone-950 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-stone-900 border border-stone-800 rounded-2xl p-8 space-y-6 shadow-2xl">
          <div className="flex justify-center">
            <div className="p-4 bg-cyan-950/30 rounded-2xl border border-cyan-500/20">
              <Shield className="w-12 h-12 text-cyan-500" />
            </div>
          </div>
          
          <div className="text-center space-y-2">
            <h1 className="text-2xl font-bold text-stone-100">SecretShield</h1>
            <p className="text-stone-400 text-sm">
              {isRegistering ? 'Create your security account' : 'Sign in to the Observatory'}
            </p>
          </div>

          <form onSubmit={isRegistering ? handleRegister : handleLogin} className="space-y-4">
            {isRegistering && (
              <div className="space-y-1">
                <label className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1">Full Name</label>
                <div className="relative">
                  <UserIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-600" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full bg-stone-950 border border-stone-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-stone-200 focus:outline-none focus:border-cyan-500 transition-all"
                  />
                </div>
              </div>
            )}
            
            <div className="space-y-1">
              <label className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-600" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@company.io"
                  className="w-full bg-stone-950 border border-stone-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-stone-200 focus:outline-none focus:border-cyan-500 transition-all"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1">Password</label>
              <div className="relative">
                <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-600" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-stone-950 border border-stone-800 rounded-xl py-2.5 pl-10 pr-4 text-sm text-stone-200 focus:outline-none focus:border-cyan-500 transition-all"
                />
              </div>
            </div>

            {error && <p className="text-xs text-rose-500 text-center font-medium">{error}</p>}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-xl font-bold transition-all shadow-lg shadow-cyan-600/20 flex items-center justify-center space-x-2"
            >
              {isLoading ? <Radio className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
              <span>{isRegistering ? 'Create Account' : 'Authenticate'}</span>
            </button>
          </form>

          <div className="relative my-2">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-stone-800" />
            </div>
            <div className="relative flex justify-center text-[10px] uppercase tracking-wider font-mono">
              <span className="bg-stone-900 px-3 text-stone-500">Quick Access</span>
            </div>
          </div>

          <button
            type="button"
            onClick={handleQuickDemoLogin}
            disabled={isLoading}
            className="w-full py-2.5 bg-stone-800/80 hover:bg-stone-800 hover:border-cyan-500/50 border border-stone-700/80 text-stone-200 rounded-xl text-xs font-semibold transition-all flex items-center justify-center space-x-2 shadow-sm"
          >
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>Enter as Demo Analyst (1-Click)</span>
          </button>

          <div className="text-center pt-2">
            <button
              onClick={() => setIsRegistering(!isRegistering)}
              className="text-xs text-stone-500 hover:text-cyan-400 transition-colors"
            >
              {isRegistering ? 'Already have an account? Sign In' : "Don't have an account? Register"}
            </button>
          </div>

          <p className="text-[10px] text-stone-500 font-mono text-center pt-4">
            TRUSTED REPOSITORY INTELLIGENCE &bull; ENTERPRISE GRADE
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-stone-950 text-stone-100 flex flex-col font-sans">
      <ObservatoryHeader
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        onLogout={handleLogout}
        user={user}
        criticalCount={metrics?.critical_count || 0}
      />

      <main className="flex-1 overflow-y-auto">
        {currentTab === 'observatory' && (
          <ObservatoryView
            metrics={metrics}
            secretsByType={secretsByType}
            repositories={repositories}
            recentScans={scans}
            recentFindings={findings}
            onNavigateTab={setCurrentTab}
            isLoading={isLoading}
          />
        )}

        {currentTab === 'scan' && (
          <ScanRepositoryView
            initialUrl={scanInitialUrl}
            onScanUrl={async (data) => {
              setIsScanning(true);
              try {
                const res = await api.triggerUrlScan({
                  url: data.url,
                  scan_scope: data.scope,
                  branch: data.branch,
                  token: data.token,
                  depth: data.depth
                });
                await loadAllData();
                return res;
              } finally {
                setIsScanning(false);
              }
            }}
            onValidateUrl={api.validateUrl}
            onPreviewUrl={api.previewRepository}
            isScanning={isScanning}
            onNavigateFindings={() => setCurrentTab('findings')}
            onNavigateObservatory={() => setCurrentTab('observatory')}
          />
        )}

        {currentTab === 'findings' && (
          <FindingsExplorer
            findings={findings}
            selectedFinding={selectedFinding}
            onSelectFinding={setSelectedFinding}
          />
        )}

        {currentTab === 'repositories' && (
          <RepositoriesObservatory
            repositories={repositories}
            onNavigateScan={(url) => {
               setScanInitialUrl(url || '');
               setCurrentTab('scan');
            }}
            onNavigateHistory={(id) => {
               setCurrentTab('reports');
            }}
          />
        )}

        {currentTab === 'exposure' && (
          <ExposureIntelligenceView
            findings={findings}
            onFetchExposure={api.getExposure}
          />
        )}

        {currentTab === 'prevention' && (
          <PreventionModeView policy={securityPolicy} />
        )}

        {currentTab === 'reports' && (
          <ReportsObservatory repositories={repositories} />
        )}

        {currentTab === 'rules' && (
          <RulesObservatory />
        )}

        {currentTab === 'settings' && (
          <SettingsObservatory />
        )}

        <div className="max-w-7xl mx-auto px-4 py-12 text-center text-stone-500 text-xs font-mono">
           &copy; 2026 SECRETSHIELD REPOSITORY OBSERVATORY &bull; VERSION 2.0.0
        </div>
      </main>
    </div>
  );
}

export default App;
