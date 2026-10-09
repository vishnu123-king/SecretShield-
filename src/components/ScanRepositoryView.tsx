import React, { useState, useEffect } from 'react';
import {
  Search,
  ArrowRight,
  ShieldCheck,
  History,
  Zap,
  Radio,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Lock,
  Globe,
  Loader2,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Key,
  GitBranch,
  Sliders,
  Sparkles,
  Layers,
  Flame,
  FileCode2,
  Download,
  Copy,
  Check,
  Code2,
  ShieldAlert,
  Cpu,
  Star,
  GitFork,
  Eye,
  AlertCircle,
  Tag,
  Calendar,
  Building,
  MapPin,
  Box,
  HardDrive,
  User,
  Users
} from 'lucide-react';
import { UrlValidationResult, RepoIntelligence, LinuxSandboxTelemetry } from '../types';

interface ScanRepositoryViewProps {
  initialUrl?: string;
  onScanUrl: (data: {
    url: string;
    scope: 'current' | 'history' | 'full';
    branch?: string;
    token?: string;
    depth?: number;
  }) => Promise<any>;
  onValidateUrl: (url: string) => Promise<UrlValidationResult>;
  onPreviewUrl: (url: string) => Promise<RepoIntelligence>;
  isScanning: boolean;
  onNavigateFindings?: () => void;
  onNavigateObservatory?: () => void;
}

const PRESET_REPOS = [
  {
    name: 'HTTP Security Header Scanner',
    url: 'https://github.com/dhivyabharathikarthi/HTTP-Security-Header-Scanner',
    tag: 'User Project',
    desc: 'Public GitHub security tool repo (Clean baseline verification)',
    type: 'github'
  },
  {
    name: 'Vulnerable Testbed Fixture',
    url: 'tests/fixtures/sample-repository',
    tag: 'Verified Leaks',
    desc: 'Local Git testbed with simulated AWS, GitHub, DB credential exposures',
    type: 'fixture'
  },
  {
    name: 'Octocat Hello-World',
    url: 'https://github.com/octocat/Hello-World',
    tag: 'GitHub Official',
    desc: 'Official GitHub demo repository with multi-branch commits',
    type: 'github'
  },
  {
    name: 'PSV Linux Security Auditor',
    url: 'https://github.com/vishnu123-king/PSV-Linux-Security-Auditor',
    tag: 'Audit Target',
    desc: 'Real-world repository with multi-branch commits and system scripts',
    type: 'github'
  }
];

export const ScanRepositoryView: React.FC<ScanRepositoryViewProps> = ({
  initialUrl = '',
  onScanUrl,
  onValidateUrl,
  onPreviewUrl,
  isScanning,
  onNavigateFindings,
  onNavigateObservatory
}) => {
  const [url, setUrl] = useState(initialUrl);
  const [isValidating, setIsValidating] = useState(false);
  const [validation, setValidation] = useState<UrlValidationResult | null>(null);
  const [preview, setPreview] = useState<RepoIntelligence | null>(null);
  const [scanScope, setScanScope] = useState<'current' | 'history' | 'full'>('history');
  
  // Advanced options
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [branch, setBranch] = useState('');
  const [token, setToken] = useState('');
  const [depth, setDepth] = useState(100);

  // Scan execution & live feedback state
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanStageIndex, setScanStageIndex] = useState(0);
  const [lastScanResult, setLastScanResult] = useState<any | null>(null);
  const [scanDurationTimer, setScanDurationTimer] = useState(0);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [copiedBadge, setCopiedBadge] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const scanStages = [
    'Provisioning isolated Linux sandbox environment (/tmp/secretshield/sandbox-linux-...)',
    'Executing secure git clone into Linux sandbox with transport isolation (protocol.ext.allow=never)',
    'Traversing unpacked working tree files & extracting Git commit diffs...',
    'Evaluating 19+ pattern rules and Shannon entropy heuristic detectors in sandbox...',
    'Synthesizing AI remediation, risk scoring, and zero-retention sandbox teardown...'
  ];

  useEffect(() => {
    if (initialUrl && initialUrl !== url) {
      setUrl(initialUrl);
    }
  }, [initialUrl]);

  // Stage animation simulator during active scanning
  useEffect(() => {
    let stageInterval: any;
    let timerInterval: any;
    if (isScanning) {
      setScanStageIndex(0);
      setScanDurationTimer(0);
      const sandboxPath = preview?.sandbox_info?.sandbox_path || `/tmp/secretshield/sandbox-linux-${Math.random().toString(36).substring(2, 9)}`;
      
      setTerminalLogs([
        `[00:00.01] 🐧 Initializing Linux ephemeral process sandbox...`,
        `[00:00.05] 📂 Mounted isolated workspace at ${sandboxPath}`,
        `[00:00.12] 🌐 Validating remote Git target: ${url.trim() || 'target'}`,
        `[00:00.22] 🔒 Transport security flags: protocol.ext.allow=never | GIT_TERMINAL_PROMPT=0`
      ]);

      timerInterval = setInterval(() => {
        setScanDurationTimer((t) => +(t + 0.1).toFixed(1));
      }, 100);

      stageInterval = setInterval(() => {
        setScanStageIndex((prev) => {
          const next = prev < scanStages.length - 1 ? prev + 1 : prev;
          setTerminalLogs((logs) => [
            ...logs,
            `[00:${String(Math.floor(Math.random() * 5 + 1)).padStart(2, '0')}.${String(Math.floor(Math.random() * 90 + 10))}] ${scanStages[next]}`
          ]);
          return next;
        });
      }, 1050);
    }
    return () => {
      clearInterval(stageInterval);
      clearInterval(timerInterval);
    };
  }, [isScanning, url, preview]);

  useEffect(() => {
    if (url.length < 3) {
      setValidation(null);
      setPreview(null);
      return;
    }
    const timer = setTimeout(async () => {
      setIsValidating(true);
      setScanError(null);
      try {
        const res = await onValidateUrl(url);
        setValidation(res);
        if (res.is_valid) {
          const prev = await onPreviewUrl(url);
          setPreview(prev);
          if (prev?.default_branch && !branch) {
            setBranch(prev.default_branch);
          }
        }
      } catch (e) {
        console.error('Validation error', e);
      } finally {
        setIsValidating(false);
      }
    }, 400);
    return () => clearTimeout(timer);
  }, [url]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validation?.is_valid && !url.includes('tests/fixtures')) return;

    setScanError(null);
    setLastScanResult(null);

    try {
      const res = await onScanUrl({
        url,
        scope: scanScope,
        branch: branch ? branch.trim() : undefined,
        token: token ? token.trim() : undefined,
        depth
      });
      setLastScanResult(res);
    } catch (err: any) {
      setScanError(err.message || 'The security scan failed. Please verify target repository is accessible.');
    }
  };

  const handleSelectPreset = (presetUrl: string) => {
    setUrl(presetUrl);
    setScanError(null);
    setLastScanResult(null);
  };

  const copyToClipboard = (text: string, type: 'badge' | 'snippet') => {
    navigator.clipboard.writeText(text);
    if (type === 'badge') {
      setCopiedBadge(true);
      setTimeout(() => setCopiedBadge(false), 2000);
    } else {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2000);
    }
  };

  const exportReport = (format: 'json' | 'csv') => {
    if (!lastScanResult) return;
    let dataStr = '';
    let filename = `secretshield-report-${Date.now()}.${format}`;

    if (format === 'json') {
      dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(lastScanResult, null, 2));
    } else {
      const headers = ['Finding ID', 'Rule Name', 'Severity', 'File', 'Line', 'Masked Secret', 'Risk Score'];
      const rows = (lastScanResult.findings || []).map((f: any) => [
        f.finding_external_id || f.findingExternalId || '',
        `"${f.rule_name || ''}"`,
        f.severity || '',
        `"${f.primary_file || ''}"`,
        f.primary_line || 1,
        `"${f.masked_secret || ''}"`,
        f.score || 50
      ]);
      const csvContent = [headers.join(','), ...rows.map((r: any) => r.join(','))].join('\n');
      dataStr = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csvContent);
    }

    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', filename);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const repoDisplayTitle = preview?.full_name || validation?.repo_name || url || 'Target Repository';
  const badgeMarkdown = `[![SecretShield: Verified Clean](https://img.shields.io/badge/SecretShield-Verified%20Clean-10b981?style=flat-square&logo=shield)](${url})`;

  const formatDate = (dateStr?: string | null) => {
    if (!dateStr) return 'N/A';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 sm:py-10 space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 bg-cyan-950/40 border border-cyan-800/40 rounded-full text-[11px] font-bold text-cyan-400 font-mono uppercase tracking-widest">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>Automated Linux Sandbox & Repository Intelligence</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-black text-stone-100 tracking-tight">
          GitHub Repository Security Scanner
        </h1>
        <p className="text-stone-400 text-sm max-w-2xl mx-auto leading-relaxed">
          Retrieve repository metadata and owner intelligence, clone into an isolated ephemeral Linux sandbox, and execute deep credential leak discovery across commit history.
        </p>
      </div>

      {/* Preset Quick Starters */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-[11px] font-mono font-bold text-stone-400 uppercase tracking-widest">
          <span className="flex items-center space-x-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Select Target Preset</span>
          </span>
          <span className="text-stone-600 text-[10px]">Click any card to auto-populate</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {PRESET_REPOS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSelectPreset(preset.url)}
              className={`p-3.5 rounded-2xl border text-left transition-all group flex flex-col justify-between space-y-2 cursor-pointer ${
                url === preset.url
                  ? 'bg-cyan-950/30 border-cyan-500/60 ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-950/40'
                  : 'bg-stone-900/80 border-stone-800 hover:border-stone-700 hover:bg-stone-900'
              }`}
            >
              <div className="flex items-center justify-between w-full">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md font-bold uppercase border ${
                  preset.tag === 'User Project'
                    ? 'bg-cyan-950 border-cyan-700/60 text-cyan-300'
                    : preset.tag === 'Verified Leaks'
                    ? 'bg-rose-950 border-rose-800/60 text-rose-300'
                    : 'bg-stone-950 border-stone-800 text-stone-400'
                }`}>
                  {preset.tag}
                </span>
                <Globe className="w-3.5 h-3.5 text-stone-600 group-hover:text-cyan-400 transition-colors" />
              </div>
              <div>
                <p className="text-xs font-bold text-stone-200 group-hover:text-stone-100">{preset.name}</p>
                <p className="text-[10px] text-stone-500 leading-snug mt-1 font-mono truncate">{preset.url}</p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Scan Form Card */}
      <div className="bg-stone-900 border border-stone-800 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-7 relative overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent"></div>
        
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target URL Input */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1">
                GitHub Repository URL
              </label>
              {validation?.is_valid && (
                <span className="text-[10px] font-mono text-emerald-400 flex items-center space-x-1 font-bold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Target Validated ({preview?.provider || 'GitHub'})</span>
                </span>
              )}
            </div>
            
            <div className="relative">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-stone-500">
                {isValidating ? (
                  <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
                ) : (
                  <Globe className="w-5 h-5 text-stone-500" />
                )}
              </div>
              <input
                type="text"
                placeholder="https://github.com/organization/project or tests/fixtures/sample-repository"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isScanning}
                className="w-full bg-stone-950 border border-stone-800 rounded-2xl py-4 pl-12 pr-4 text-stone-100 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all font-mono text-sm"
              />
            </div>

            {validation && !validation.is_valid && (
              <p className="text-rose-400 text-xs font-mono mt-2 ml-1 flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                <span>{validation.error}</span>
              </p>
            )}
          </div>

          {/* GitHub Repository Intelligence & Owner Details */}
          {preview && (
            <div className="space-y-4 animate-in slide-in-from-bottom-2 duration-300">
              <div className="flex items-center space-x-2 text-[11px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Repository &amp; Owner Intelligence</span>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* 1. Repository Owner Details Card */}
                <div className="bg-stone-950/70 border border-stone-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase text-stone-500 font-bold tracking-wider">Repository Owner</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-stone-900 border border-stone-800 text-cyan-400 font-bold">
                        {preview.owner.type || 'User'}
                      </span>
                    </div>

                    <div className="flex items-center space-x-3.5">
                      {preview.owner.avatar_url ? (
                        <img
                          src={preview.owner.avatar_url}
                          alt={preview.owner.login}
                          className="w-12 h-12 rounded-xl border border-stone-700 object-cover shadow-sm"
                        />
                      ) : (
                        <div className="w-12 h-12 rounded-xl bg-stone-900 border border-stone-700 flex items-center justify-center">
                          <User className="w-6 h-6 text-stone-400" />
                        </div>
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center space-x-1.5">
                          <h4 className="text-sm font-bold text-stone-100 truncate">{preview.owner.name || preview.owner.login}</h4>
                          {preview.owner.profile_url && (
                            <a
                              href={preview.owner.profile_url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-stone-500 hover:text-cyan-400 transition-colors"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                        </div>
                        <p className="text-xs text-stone-400 font-mono truncate">@{preview.owner.login}</p>
                      </div>
                    </div>

                    {preview.owner.bio && (
                      <p className="text-xs text-stone-400 line-clamp-2 leading-relaxed">
                        {preview.owner.bio}
                      </p>
                    )}
                  </div>

                  <div className="pt-3 border-t border-stone-900 text-[11px] text-stone-400 font-mono space-y-1">
                    {preview.owner.company && (
                      <p className="flex items-center space-x-1.5 truncate">
                        <Building className="w-3.5 h-3.5 text-stone-500 flex-shrink-0" />
                        <span>{preview.owner.company}</span>
                      </p>
                    )}
                    {preview.owner.location && (
                      <p className="flex items-center space-x-1.5 truncate">
                        <MapPin className="w-3.5 h-3.5 text-stone-500 flex-shrink-0" />
                        <span>{preview.owner.location}</span>
                      </p>
                    )}
                    {preview.owner.public_repos !== undefined && (
                      <p className="flex items-center space-x-1.5 text-stone-500">
                        <Box className="w-3.5 h-3.5 flex-shrink-0" />
                        <span>{preview.owner.public_repos} public repos</span>
                      </p>
                    )}
                  </div>
                </div>

                {/* 2. About Repository Card */}
                <div className="lg:col-span-2 bg-stone-950/70 border border-stone-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                  <div className="space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <h3 className="text-base font-bold text-stone-100">{preview.name}</h3>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 font-bold">
                          {preview.visibility}
                        </span>
                      </div>
                      {preview.web_url && (
                        <a
                          href={preview.web_url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                        >
                          <span>View on GitHub</span>
                          <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>

                    <p className="text-xs text-stone-300 leading-relaxed">
                      {preview.description || 'Public Git repository security audit target.'}
                    </p>

                    {/* Topics */}
                    {preview.topics && preview.topics.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {preview.topics.slice(0, 6).map((topic, tidx) => (
                          <span
                            key={tidx}
                            className="px-2 py-0.5 rounded-md bg-stone-900 border border-stone-800 text-[10px] font-mono text-cyan-300 flex items-center space-x-1"
                          >
                            <Tag className="w-2.5 h-2.5 text-stone-500" />
                            <span>{topic}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Repo Stats Row */}
                  <div className="pt-3 border-t border-stone-900 grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs">
                    <div className="p-2 bg-stone-900/60 rounded-xl border border-stone-800/80">
                      <p className="text-[9px] font-mono uppercase text-stone-500 flex items-center justify-center space-x-1">
                        <Star className="w-3 h-3 text-amber-400" />
                        <span>Stars</span>
                      </p>
                      <p className="font-bold text-stone-200 mt-0.5">{preview.stars}</p>
                    </div>

                    <div className="p-2 bg-stone-900/60 rounded-xl border border-stone-800/80">
                      <p className="text-[9px] font-mono uppercase text-stone-500 flex items-center justify-center space-x-1">
                        <GitFork className="w-3 h-3 text-stone-400" />
                        <span>Forks</span>
                      </p>
                      <p className="font-bold text-stone-200 mt-0.5">{preview.forks}</p>
                    </div>

                    <div className="p-2 bg-stone-900/60 rounded-xl border border-stone-800/80">
                      <p className="text-[9px] font-mono uppercase text-stone-500 flex items-center justify-center space-x-1">
                        <Code2 className="w-3 h-3 text-cyan-400" />
                        <span>Language</span>
                      </p>
                      <p className="font-bold text-stone-200 mt-0.5 truncate">{preview.language || 'Code'}</p>
                    </div>

                    <div className="p-2 bg-stone-900/60 rounded-xl border border-stone-800/80">
                      <p className="text-[9px] font-mono uppercase text-stone-500 flex items-center justify-center space-x-1">
                        <GitBranch className="w-3 h-3 text-emerald-400" />
                        <span>Branch</span>
                      </p>
                      <p className="font-bold text-stone-200 mt-0.5 truncate">{preview.default_branch || 'main'}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* 3. Linux Sandbox Isolation Specification Card */}
              <div className="bg-gradient-to-r from-stone-950 via-stone-900 to-stone-950 border border-cyan-900/40 rounded-2xl p-4 sm:p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="flex items-center space-x-3.5">
                  <div className="p-2.5 bg-cyan-950/60 border border-cyan-800/50 rounded-xl text-cyan-400">
                    <Terminal className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h4 className="text-xs font-mono font-bold text-stone-200">Linux Ephemeral Sandbox Environment</h4>
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-700/60 text-emerald-400 font-bold">
                        ISOLATION ACTIVE
                      </span>
                    </div>
                    <p className="text-[11px] text-stone-400 font-mono mt-0.5 truncate max-w-md">
                      Target Workspace: <span className="text-cyan-300">{preview.sandbox_info?.sandbox_path}</span>
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-stone-400">
                  <span className="flex items-center space-x-1">
                    <HardDrive className="w-3.5 h-3.5 text-stone-500" />
                    <span>{preview.size_mb} MB</span>
                  </span>
                  <span className="text-stone-700">&bull;</span>
                  <span className="flex items-center space-x-1">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Zero-Retention</span>
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Scan Scope Selection */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <button
              type="button"
              disabled={isScanning}
              onClick={() => setScanScope('current')}
              className={`p-4 rounded-2xl border text-left transition-all space-y-2 cursor-pointer ${
                scanScope === 'current'
                  ? 'bg-stone-800/80 border-cyan-500/50 ring-1 ring-cyan-500/30'
                  : 'bg-stone-950/40 border-stone-800 hover:border-stone-700'
              }`}
            >
              <Zap className={`w-4 h-4 ${scanScope === 'current' ? 'text-cyan-400' : 'text-stone-500'}`} />
              <p className="text-xs font-bold text-stone-200 uppercase">Quick Scan</p>
              <p className="text-[10px] text-stone-500 leading-relaxed font-mono">Current HEAD & working tree in Linux sandbox.</p>
            </button>
            <button
              type="button"
              disabled={isScanning}
              onClick={() => setScanScope('history')}
              className={`p-4 rounded-2xl border text-left transition-all space-y-2 cursor-pointer ${
                scanScope === 'history'
                  ? 'bg-stone-800/80 border-cyan-500/50 ring-1 ring-cyan-500/30'
                  : 'bg-stone-950/40 border-stone-800 hover:border-stone-700'
              }`}
            >
              <History className={`w-4 h-4 ${scanScope === 'history' ? 'text-cyan-400' : 'text-stone-500'}`} />
              <p className="text-xs font-bold text-stone-200 uppercase">Deep Scan</p>
              <p className="text-[10px] text-stone-500 leading-relaxed font-mono">Working files + commit diff history up to {depth} commits.</p>
            </button>
            <button
              type="button"
              disabled={isScanning}
              onClick={() => setScanScope('full')}
              className={`p-4 rounded-2xl border text-left transition-all space-y-2 cursor-pointer ${
                scanScope === 'full'
                  ? 'bg-stone-800/80 border-cyan-500/50 ring-1 ring-cyan-500/30'
                  : 'bg-stone-950/40 border-stone-800 hover:border-stone-700'
              }`}
            >
              <Layers className={`w-4 h-4 ${scanScope === 'full' ? 'text-cyan-400' : 'text-stone-500'}`} />
              <p className="text-xs font-bold text-stone-200 uppercase">Full Audit</p>
              <p className="text-[10px] text-stone-500 leading-relaxed font-mono">All branches, remote refs, and deep commit history.</p>
            </button>
          </div>

          {/* Advanced Configuration Toggle */}
          <div className="border-t border-stone-800/70 pt-4">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center space-x-2 text-xs font-mono text-stone-400 hover:text-cyan-400 transition-colors cursor-pointer"
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Advanced Parameters (Branch, Private Token, Depth)</span>
              {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {showAdvanced && (
              <div className="mt-4 p-5 bg-stone-950/50 border border-stone-800 rounded-2xl space-y-4 animate-in fade-in duration-200">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono uppercase text-stone-400 font-bold flex items-center space-x-1.5">
                      <GitBranch className="w-3 h-3 text-stone-500" />
                      <span>Target Branch</span>
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. main, master, dev"
                      value={branch}
                      onChange={(e) => setBranch(e.target.value)}
                      className="w-full bg-stone-900 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono uppercase text-stone-400 font-bold flex items-center space-x-1.5">
                      <Key className="w-3 h-3 text-stone-500" />
                      <span>Personal Access Token (Private Repos)</span>
                    </label>
                    <input
                      type="password"
                      placeholder="ghp_... or glpat-... (optional)"
                      value={token}
                      onChange={(e) => setToken(e.target.value)}
                      className="w-full bg-stone-900 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between text-[10px] font-mono text-stone-400">
                    <span>Commit History Depth</span>
                    <span className="font-bold text-cyan-400">{depth} commits</span>
                  </div>
                  <input
                    type="range"
                    min="10"
                    max="250"
                    step="10"
                    value={depth}
                    onChange={(e) => setDepth(parseInt(e.target.value, 10))}
                    className="w-full accent-cyan-500 bg-stone-900 cursor-pointer"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Submit Action Button */}
          <button
            type="submit"
            disabled={!validation?.is_valid || isScanning}
            className="w-full py-4 bg-cyan-600 hover:bg-cyan-500 disabled:bg-stone-800 disabled:text-stone-600 text-white rounded-2xl font-black text-sm uppercase tracking-[0.2em] transition-all shadow-xl shadow-cyan-600/20 flex items-center justify-center space-x-3 cursor-pointer group"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin text-white" />
                <span>Executing Linux Sandbox Clone &amp; Audit ({scanDurationTimer}s)...</span>
              </>
            ) : (
              <>
                <Terminal className="w-5 h-5" />
                <span>Deploy Linux Sandbox &amp; Start Analysis</span>
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </>
            )}
          </button>

          {/* Error Banner */}
          {scanError && (
            <div className="p-4 bg-rose-950/20 border border-rose-900/40 rounded-2xl flex items-start space-x-3 animate-in shake duration-300">
              <AlertTriangle className="w-5 h-5 text-rose-500 flex-shrink-0 mt-0.5" />
              <div className="space-y-1 text-left">
                <p className="text-xs font-bold text-rose-400">Scan Execution Failed</p>
                <p className="text-xs text-stone-300 font-mono leading-relaxed">{scanError}</p>
                {scanError.toLowerCase().includes('private') || scanError.toLowerCase().includes('authentication') ? (
                  <div className="pt-2">
                    <p className="text-[11px] text-cyan-400 font-mono">
                      Tip: This repository appears to be private or requires credentials. Expand "Advanced Parameters" above and provide a GitHub Personal Access Token (PAT).
                    </p>
                    <button
                      type="button"
                      onClick={() => setShowAdvanced(true)}
                      className="mt-2 text-xs font-bold text-cyan-300 underline cursor-pointer"
                    >
                      Open Token Input &rarr;
                    </button>
                  </div>
                ) : null}
              </div>
            </div>
          )}

          {/* Live Scanning Terminal Animation */}
          {isScanning && (
            <div className="bg-stone-950 border border-stone-800 rounded-2xl p-5 space-y-4 shadow-inner animate-in fade-in duration-300">
              <div className="flex items-center justify-between border-b border-stone-800 pb-3">
                <div className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-stone-300">Active Linux Sandbox Telemetry</span>
                </div>
                <div className="flex items-center space-x-3 text-[10px] font-mono text-cyan-400">
                  <span className="text-stone-400">{scanDurationTimer}s elapsed</span>
                  <div className="flex items-center space-x-1.5 font-bold">
                    <Radio className="w-3 h-3 animate-pulse" />
                    <span>PHASE {scanStageIndex + 1}/5</span>
                  </div>
                </div>
              </div>

              {/* Progress steps */}
              <div className="space-y-2">
                {scanStages.map((stage, i) => (
                  <div key={i} className="flex items-center space-x-3 text-xs font-mono">
                    {i < scanStageIndex ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    ) : i === scanStageIndex ? (
                      <Loader2 className="w-4 h-4 text-cyan-400 animate-spin flex-shrink-0" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-stone-700 flex-shrink-0"></div>
                    )}
                    <span className={i === scanStageIndex ? 'text-stone-100 font-bold' : (i < scanStageIndex ? 'text-stone-400' : 'text-stone-600')}>
                      {stage}
                    </span>
                  </div>
                ))}
              </div>

              {/* Live terminal diagnostic output */}
              <div className="mt-4 p-3 bg-stone-900/90 border border-stone-800/80 rounded-xl font-mono text-[11px] text-stone-400 space-y-1 max-h-40 overflow-y-auto">
                {terminalLogs.map((log, lidx) => (
                  <p key={lidx} className="leading-snug">
                    <span className="text-cyan-500">&gt;</span> {log}
                  </p>
                ))}
              </div>
            </div>
          )}

          {/* Post-Scan Results Hub */}
          {lastScanResult && !isScanning && (
            <div className="bg-stone-950/80 border border-cyan-800/50 rounded-2xl p-6 space-y-6 shadow-2xl animate-in slide-in-from-bottom-3 duration-300">
              {/* Header Status */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-stone-800">
                <div className="flex items-center space-x-3">
                  <div className={`p-2.5 rounded-xl border ${
                    (lastScanResult.summary?.total_findings || 0) === 0
                      ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-400'
                      : 'bg-rose-950/40 border-rose-800/50 text-rose-400'
                  }`}>
                    {(lastScanResult.summary?.total_findings || 0) === 0 ? (
                      <ShieldCheck className="w-6 h-6" />
                    ) : (
                      <ShieldAlert className="w-6 h-6" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-stone-100">
                      {(lastScanResult.summary?.total_findings || 0) === 0
                        ? 'Audit Completed: Clean Repository'
                        : `Audit Completed: ${lastScanResult.summary?.total_findings} Secrets Detected`}
                    </h3>
                    <p className="text-xs text-stone-400 font-mono mt-0.5">
                      Analyzed in {lastScanResult.summary?.duration || 0}s &bull; Risk Score: {lastScanResult.summary?.risk_index || 0}/100
                    </p>
                  </div>
                </div>

                {/* Export Buttons */}
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => exportReport('json')}
                    className="px-3 py-1.5 bg-stone-900 hover:bg-stone-800 border border-stone-800 rounded-lg text-xs font-mono text-stone-300 flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-stone-400" />
                    <span>JSON</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => exportReport('csv')}
                    className="px-3 py-1.5 bg-stone-900 hover:bg-stone-800 border border-stone-800 rounded-lg text-xs font-mono text-stone-300 flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-stone-400" />
                    <span>CSV</span>
                  </button>
                </div>
              </div>

              {/* Linux Sandbox Execution Telemetry Badge */}
              {lastScanResult.sandbox && (
                <div className="p-3.5 bg-stone-900/90 border border-stone-800 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
                  <div className="flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                    <span className="text-stone-300 font-bold">Linux Sandbox ID:</span>
                    <span className="text-cyan-300">{lastScanResult.sandbox.sandbox_id || 'sandbox-linux'}</span>
                  </div>
                  <div className="flex items-center space-x-3 text-stone-400 text-[11px]">
                    <span>{lastScanResult.sandbox.platform || 'Linux Container'}</span>
                    <span>&bull;</span>
                    <span className="text-emerald-400 font-bold">{lastScanResult.sandbox.status || 'Purged & Zero-Retained'}</span>
                  </div>
                </div>
              )}

              {/* Metric Counters */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                <div className="p-3 bg-stone-900 border border-stone-800 rounded-xl">
                  <p className="text-[9px] font-black uppercase text-stone-500">Total Secrets</p>
                  <p className="text-2xl font-black text-stone-100 mt-0.5">{lastScanResult.summary?.total_findings || 0}</p>
                </div>
                <div className="p-3 bg-rose-950/20 border border-rose-900/30 rounded-xl">
                  <p className="text-[9px] font-black uppercase text-rose-500">Critical</p>
                  <p className="text-2xl font-black text-rose-400 mt-0.5">{lastScanResult.summary?.critical || 0}</p>
                </div>
                <div className="p-3 bg-amber-950/20 border border-amber-900/30 rounded-xl">
                  <p className="text-[9px] font-black uppercase text-amber-500">High</p>
                  <p className="text-2xl font-black text-amber-400 mt-0.5">{lastScanResult.summary?.high || 0}</p>
                </div>
                <div className="p-3 bg-cyan-950/20 border border-cyan-900/30 rounded-xl">
                  <p className="text-[9px] font-black uppercase text-cyan-500">Medium/Low</p>
                  <p className="text-2xl font-black text-cyan-400 mt-0.5">
                    {(lastScanResult.summary?.medium || 0) + (lastScanResult.summary?.low || 0)}
                  </p>
                </div>
              </div>

              {/* Zero Findings Celebration Card */}
              {(lastScanResult.summary?.total_findings || 0) === 0 ? (
                <div className="p-5 bg-emerald-950/20 border border-emerald-900/40 rounded-2xl space-y-4">
                  <div className="flex items-center space-x-3 text-emerald-400">
                    <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
                    <p className="text-sm font-bold">No Leaked Credentials Detected in Working Tree or Commits</p>
                  </div>
                  <p className="text-xs text-stone-300 font-mono leading-relaxed">
                    Repository <span className="text-emerald-300 font-bold">{repoDisplayTitle}</span> verified clean against 19+ pattern rules and Shannon entropy heuristics in the Linux sandbox.
                  </p>
                  
                  {/* README Badge Generator */}
                  <div className="pt-2 border-t border-emerald-900/30 space-y-2">
                    <div className="flex items-center justify-between text-[11px] font-mono font-bold text-stone-400">
                      <span>Add Verification Badge to GitHub README</span>
                      <button
                        type="button"
                        onClick={() => copyToClipboard(badgeMarkdown, 'badge')}
                        className="text-emerald-400 hover:text-emerald-300 flex items-center space-x-1 cursor-pointer"
                      >
                        {copiedBadge ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedBadge ? 'Copied!' : 'Copy Markdown'}</span>
                      </button>
                    </div>
                    <div className="p-2.5 bg-stone-900 border border-stone-800 rounded-xl flex items-center justify-between font-mono text-xs text-stone-300 overflow-x-auto">
                      <code className="text-[11px] text-emerald-300 truncate">{badgeMarkdown}</code>
                    </div>
                  </div>
                </div>
              ) : (
                /* Findings Table Preview */
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-stone-400">
                      Detected Secrets ({lastScanResult.findings?.length || 0})
                    </h4>
                    {onNavigateFindings && (
                      <button
                        type="button"
                        onClick={onNavigateFindings}
                        className="text-xs font-mono text-cyan-400 hover:text-cyan-300 font-bold flex items-center space-x-1 cursor-pointer"
                      >
                        <span>Open Findings Explorer</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>

                  <div className="border border-stone-800 rounded-xl overflow-hidden divide-y divide-stone-800/80">
                    {(lastScanResult.findings || []).slice(0, 5).map((f: any, i: number) => (
                      <div key={i} className="p-3.5 bg-stone-900/60 hover:bg-stone-900 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                              f.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                              f.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            }`}>
                              {f.severity}
                            </span>
                            <span className="font-bold text-stone-200">{f.rule_name || f.ruleName}</span>
                          </div>
                          <p className="font-mono text-[11px] text-stone-400">
                            {f.primary_file || f.primaryFile}:{f.primary_line || f.primaryLine || 1}
                          </p>
                        </div>
                        <div className="font-mono text-[11px] bg-stone-950 px-2.5 py-1 rounded-lg border border-stone-800 text-stone-300">
                          {f.masked_secret || f.maskedSecret || '••••••••'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Navigation Action Buttons */}
              <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
                {onNavigateFindings && (
                  <button
                    type="button"
                    onClick={onNavigateFindings}
                    className="w-full sm:flex-1 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-cyan-600/20 flex items-center justify-center space-x-2 cursor-pointer"
                  >
                    <FileCode2 className="w-4 h-4" />
                    <span>Explore Findings in Workbench &rarr;</span>
                  </button>
                )}
                {onNavigateObservatory && (
                  <button
                    type="button"
                    onClick={onNavigateObservatory}
                    className="w-full sm:w-auto px-6 py-3 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-xs font-bold border border-stone-700 transition-all cursor-pointer"
                  >
                    View Observatory Deck
                  </button>
                )}
              </div>
            </div>
          )}
        </form>
      </div>

      {/* CI/CD & Automated Prevention Guide */}
      <div className="bg-stone-900/60 border border-stone-800 rounded-3xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <Code2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-stone-200">
              CI/CD Automation &amp; Pre-Commit Guard
            </h3>
          </div>
          <button
            type="button"
            onClick={() => copyToClipboard(`name: SecretShield Scan
on: [push, pull_request]
jobs:
  secret-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run SecretShield Guard
        run: |
          python3 cli/secretshield.py scan . --mode deep --format json`, 'snippet')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 cursor-pointer"
          >
            {copiedSnippet ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedSnippet ? 'Copied Action YAML!' : 'Copy GitHub Action'}</span>
          </button>
        </div>
        <p className="text-xs text-stone-400 font-mono leading-relaxed">
          Prevent credentials from ever reaching production. Add SecretShield to your GitHub Actions workflow or install the local pre-commit hook to block commits with unmasked tokens.
        </p>
        <div className="p-3 bg-stone-950 border border-stone-800/80 rounded-xl font-mono text-xs text-cyan-300">
          <code>python3 cli/secretshield.py install-hook</code>
        </div>
      </div>

      {/* Security Principles Footer */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4">
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-[10px] font-black text-stone-500 uppercase tracking-widest">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Zero-Retention Ephemeral Sandbox</span>
          </div>
          <p className="text-xs text-stone-400 leading-relaxed font-mono">
            Repositories are cloned into isolated, temporary sandboxes under /tmp/secretshield and destroyed immediately upon audit completion. Plaintext secrets are never written to database tables—only SHA-256 fingerprints and masked contexts.
          </p>
        </div>
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-[10px] font-black text-stone-500 uppercase tracking-widest">
            <ExternalLink className="w-3.5 h-3.5 text-emerald-400" />
            <span>Supported Version Control Hosts</span>
          </div>
          <div className="flex flex-wrap gap-2 text-xs font-mono font-bold text-stone-300">
             <span className="px-2.5 py-1 bg-stone-900 border border-stone-800 rounded-lg">GitHub</span>
             <span className="px-2.5 py-1 bg-stone-900 border border-stone-800 rounded-lg">GitLab</span>
             <span className="px-2.5 py-1 bg-stone-900 border border-stone-800 rounded-lg">Bitbucket</span>
             <span className="px-2.5 py-1 bg-stone-900 border border-stone-800 rounded-lg">Forgejo / Gitea</span>
             <span className="px-2.5 py-1 bg-stone-900 border border-stone-800 rounded-lg">Local Fixtures</span>
          </div>
        </div>
      </div>
    </div>
  );
};
