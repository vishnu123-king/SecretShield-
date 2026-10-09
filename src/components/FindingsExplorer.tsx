import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowRight,
  ChevronRight,
  FileCode2,
  GitCommit,
  Clock,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  RotateCcw,
  Copy,
  Check,
  Zap,
  Github,
  Key,
  FileText,
  UserCheck,
  X,
  Send,
  AlertCircle,
  HelpCircle,
  Lock
} from 'lucide-react';
import { Finding, FindingStatus } from '../types';
import { api } from '../services/api';

interface FindingsExplorerProps {
  findings: Finding[];
  selectedFinding: Finding | null;
  onSelectFinding: (finding: Finding | null) => void;
  onRefreshFindings?: () => void;
}

export const FindingsExplorer: React.FC<FindingsExplorerProps> = ({
  findings,
  selectedFinding,
  onSelectFinding,
  onRefreshFindings
}) => {
  const [searchTerm, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copied, setCopied] = useState(false);
  const [copiedIssue, setCopiedIssue] = useState(false);

  // Modals state
  const [showIssueModal, setShowIssueModal] = useState(false);
  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [showSignOffModal, setShowSignOffModal] = useState(false);

  // Sign-Off Form State
  const [signOffStatus, setSignOffStatus] = useState<string>('False Positive');
  const [justification, setJustification] = useState('');
  const [approverName, setApproverName] = useState('');
  const [expiryOption, setExpiryOption] = useState('90_days');
  const [isSubmittingSignOff, setIsSubmittingSignOff] = useState(false);
  const [signOffSuccess, setSignOffSuccess] = useState(false);

  // Revocation Simulator State
  const [revocationStep, setRevocationStep] = useState(0);
  const [isVerifyingRevocation, setIsVerifyingRevocation] = useState(false);
  const [revocationVerified, setRevocationVerified] = useState(false);

  const filteredFindings = findings.filter(f => {
    const matchesSearch = 
      f.rule_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.repository_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.primary_file.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Generate GitHub Issue Markdown
  const generateIssueMarkdown = (f: Finding) => {
    return `### 🚨 Security Vulnerability: Exposed ${f.rule_name} Detected

**Severity:** ${f.severity}
**Investigation ID:** ${f.finding_id}
**Repository:** ${f.repository_name}
**File Path:** \`${f.primary_file}:${f.primary_line}\`
**Status:** ${f.is_currently_present ? '🔴 Active Exposure in HEAD' : '🟡 Historical Commit Exposure'}

---

#### 🔍 Finding Context
SecretShield discovered an exposed credential matching the **${f.rule_name}** deterministic pattern.
- **Masked Token:** \`${f.masked_secret}\`
- **Shannon Entropy Score:** Elevated randomness
- **Risk Score:** ${f.score} / 100

#### ⚠️ Risk Analysis
${f.ai_explanation || 'Exposure of this credential grants unauthorized upstream access or data traversal.'}

#### 🛠️ Immediate Remediation Steps
${f.remediation || '1. Immediately revoke the exposed token at the upstream provider portal.\n2. Invalidate active sessions.\n3. Remove from code and inject via environment variables.'}

---
*Reported automatically via [SecretShield Repository Security Observatory](https://github.com/)*`;
  };

  const openGitHubIssueDirectly = (f: Finding) => {
    const repo = f.repository_name.includes('/') ? f.repository_name : `organization/${f.repository_name}`;
    const title = encodeURIComponent(`[SECURITY] Credentials Exposed: ${f.rule_name} in ${f.primary_file}`);
    const body = encodeURIComponent(generateIssueMarkdown(f));
    const url = `https://github.com/${repo}/issues/new?title=${title}&body=${body}&labels=security,secret-leak,p0-urgent`;
    window.open(url, '_blank');
  };

  const handleSignOffSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFinding) return;
    setIsSubmittingSignOff(true);
    try {
      await api.updateFindingStatus(selectedFinding.id, {
        status: signOffStatus,
        resolutionNote: justification,
        approverName: approverName || 'Security Lead',
        expiryDate: expiryOption === 'permanent' ? 'Permanent' : '90 Days'
      });
      setSignOffSuccess(true);
      setTimeout(() => {
        setSignOffSuccess(false);
        setShowSignOffModal(false);
        if (onRefreshFindings) onRefreshFindings();
      }, 1500);
    } catch (err: any) {
      alert(`Error updating status: ${err.message}`);
    } finally {
      setIsSubmittingSignOff(false);
    }
  };

  const handleSimulateRevocationCheck = () => {
    setIsVerifyingRevocation(true);
    setTimeout(() => {
      setIsVerifyingRevocation(false);
      setRevocationVerified(true);
    }, 1400);
  };

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden">
      {/* Sidebar List */}
      <div className="w-96 border-r border-stone-800 bg-stone-900/50 flex flex-col">
        <div className="p-4 border-b border-stone-800 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-black text-stone-500 uppercase tracking-[0.2em]">Security Deck</h2>
            <span className="text-[10px] font-mono text-cyan-400 font-bold bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/50">
              {filteredFindings.length} Total
            </span>
          </div>
          
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-stone-500" />
            <input
              type="text"
              placeholder="Filter findings..."
              value={searchTerm}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-stone-950 border border-stone-800 rounded-xl py-2 pl-10 pr-4 text-xs text-stone-100 focus:outline-none focus:border-cyan-500 transition-all font-mono"
            />
          </div>

          <div className="flex items-center space-x-1.5 overflow-x-auto pt-1">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition-all cursor-pointer ${
                  severityFilter === sev
                    ? 'bg-stone-800 text-cyan-400 border border-stone-700'
                    : 'text-stone-500 hover:text-stone-300'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-stone-800/50">
          {filteredFindings.map((f) => (
            <button
              key={f.id}
              onClick={() => onSelectFinding(f)}
              className={`w-full p-4 text-left transition-all hover:bg-stone-800/30 group cursor-pointer ${
                selectedFinding?.id === f.id ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                  f.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400 border border-rose-900/40' :
                  f.severity === 'HIGH' ? 'bg-amber-500/10 text-amber-400 border border-amber-900/40' :
                  'bg-cyan-500/10 text-cyan-400 border border-cyan-900/40'
                }`}>
                  {f.severity}
                </span>
                <span className="text-[10px] text-stone-600 font-mono">#{f.finding_id}</span>
              </div>
              <p className="text-xs font-bold text-stone-200 truncate group-hover:text-cyan-400 transition-colors">{f.rule_name}</p>
              <p className="text-[10px] text-stone-500 font-mono mt-1 truncate">{f.repository_name} &bull; {f.primary_file}</p>
              <div className="flex items-center justify-between mt-3">
                <span className={`text-[10px] font-mono uppercase font-bold tracking-widest ${
                  f.status === 'Resolved' || f.status === 'False Positive' ? 'text-emerald-400' : 'text-stone-500'
                }`}>
                  {f.status}
                </span>
                <ChevronRight className="w-3 h-3 text-stone-700 group-hover:text-stone-400 transition-transform" />
              </div>
            </button>
          ))}
          {filteredFindings.length === 0 && (
            <div className="py-20 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-stone-800 mx-auto" />
              <p className="text-xs text-stone-600 font-mono">No findings match query.</p>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 bg-stone-950 overflow-y-auto">
        {selectedFinding ? (
          <div className="p-6 sm:p-8 max-w-5xl mx-auto space-y-8 animate-in slide-in-from-right-4 duration-300">
            {/* Header & Quick Action Buttons */}
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 border-b border-stone-800 pb-8">
              <div className="space-y-4">
                <div className="flex items-center space-x-3">
                  <div className={`p-2.5 rounded-xl ${selectedFinding.severity === 'CRITICAL' ? 'bg-rose-500/10 border border-rose-900/40' : 'bg-amber-500/10 border border-amber-900/40'}`}>
                    <ShieldAlert className={`w-6 h-6 ${selectedFinding.severity === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'}`} />
                  </div>
                  <div>
                    <h1 className="text-2xl font-black text-stone-100 tracking-tight">{selectedFinding.rule_name}</h1>
                    <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
                      Investigation ID: {selectedFinding.finding_id} &bull; Risk Score: {selectedFinding.score}/100 &bull; Status: <span className="text-cyan-400 font-bold">{selectedFinding.status}</span>
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <span className="px-3 py-1 bg-stone-900 border border-stone-800 rounded-lg text-[10px] font-bold text-stone-400 font-mono">
                    {selectedFinding.repository_name}
                  </span>
                  <span className="px-3 py-1 bg-stone-900 border border-stone-800 rounded-lg text-[10px] font-bold text-stone-400 font-mono">
                    {selectedFinding.secret_type}
                  </span>
                  <span className="px-3 py-1 bg-stone-900 border border-stone-800 rounded-lg text-[10px] font-bold text-stone-400 font-mono">
                    {selectedFinding.is_currently_present ? 'Active Exposure' : 'Historical Leak'}
                  </span>
                </div>
              </div>

              {/* Action Toolbar */}
              <div className="flex flex-wrap items-center gap-2.5">
                {/* 1. One-Click GitHub Issue Creator */}
                <button
                  onClick={() => setShowIssueModal(true)}
                  className="px-3.5 py-2 bg-stone-900 hover:bg-stone-800 border border-stone-800 text-stone-200 hover:text-white rounded-xl text-xs font-bold transition-all flex items-center space-x-2 cursor-pointer shadow-sm"
                >
                  <Github className="w-3.5 h-3.5 text-stone-400" />
                  <span>Create GitHub Issue</span>
                </button>

                {/* 2. Automated Secret Revocation Advisor */}
                <button
                  onClick={() => setShowRevokeModal(true)}
                  className="px-3.5 py-2 bg-rose-950/40 hover:bg-rose-900/50 border border-rose-900/50 text-rose-300 rounded-xl text-xs font-bold transition-all flex items-center space-x-2 cursor-pointer shadow-sm"
                >
                  <Key className="w-3.5 h-3.5" />
                  <span>Revoke Key</span>
                </button>

                {/* 3. Formal Exception & Sign-Off Management */}
                <button
                  onClick={() => setShowSignOffModal(true)}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold transition-all flex items-center space-x-2 cursor-pointer shadow-lg shadow-cyan-600/20"
                >
                  <UserCheck className="w-3.5 h-3.5" />
                  <span>Sign-Off Exception</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="lg:col-span-2 space-y-8">
                {/* Code Context */}
                <div className="space-y-4">
                  <h3 className="text-xs font-black text-stone-500 uppercase tracking-widest flex items-center space-x-2">
                    <FileCode2 className="w-4 h-4" />
                    <span>Masked Evidence Context</span>
                  </h3>
                  <div className="bg-stone-900 border border-stone-800 rounded-2xl overflow-hidden shadow-inner">
                    <div className="bg-stone-950/50 px-4 py-2 border-b border-stone-800 flex items-center justify-between">
                      <span className="text-[10px] text-stone-500 font-mono">{selectedFinding.primary_file}</span>
                      <button onClick={() => handleCopy(selectedFinding.masked_secret)} className="text-stone-500 hover:text-stone-300 p-1 cursor-pointer">
                        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                    <div className="p-4 font-mono text-xs leading-relaxed space-y-1">
                      {selectedFinding.context?.snippet?.map((line: any, i: number) => (
                        <div key={i} className={`flex ${line.is_target ? 'bg-rose-500/10 -mx-4 px-4 border-l-2 border-rose-500' : ''}`}>
                          <span className="w-8 text-stone-700 text-right pr-4 select-none">{line.line_number}</span>
                          <span className={`${line.is_target ? 'text-rose-400 font-bold' : 'text-stone-400'}`}>{line.content}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* AI Analysis */}
                <div className="space-y-4">
                  <h3 className="text-xs font-black text-stone-500 uppercase tracking-widest flex items-center space-x-2">
                    <Zap className="w-4 h-4 text-cyan-500" />
                    <span>AI-Assisted Assessment</span>
                  </h3>
                  <div className="bg-cyan-950/10 border border-cyan-800/30 rounded-2xl p-6 space-y-4 shadow-lg shadow-cyan-500/5">
                    <p className="text-sm text-stone-200 leading-relaxed italic">
                      "{selectedFinding.ai_explanation}"
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {selectedFinding.evidence_points?.map((point, i) => (
                        <div key={i} className="flex items-center space-x-2 text-[10px] font-mono text-stone-400">
                          <div className="w-1.5 h-1.5 bg-cyan-500 rounded-full flex-shrink-0"></div>
                          <span>{point}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Audit & Exception Sign-off History Logs */}
                {selectedFinding.history_logs && selectedFinding.history_logs.length > 0 && (
                  <div className="space-y-4">
                    <h3 className="text-xs font-black text-stone-500 uppercase tracking-widest flex items-center space-x-2">
                      <Clock className="w-4 h-4" />
                      <span>Governance Audit Trail</span>
                    </h3>
                    <div className="bg-stone-900/60 border border-stone-800 rounded-2xl p-4 divide-y divide-stone-800/80 font-mono text-xs">
                      {selectedFinding.history_logs.map((log: any, idx: number) => (
                        <div key={idx} className="py-2.5 first:pt-0 last:pb-0 space-y-1">
                          <div className="flex items-center justify-between text-[10px] text-stone-500">
                            <span>Status changed to <strong className="text-cyan-400">{log.new_status}</strong></span>
                            <span>{new Date(log.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-stone-300 text-xs">{log.note}</p>
                          {log.approver && (
                            <p className="text-[10px] text-stone-500">Approver: {log.approver}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-8">
                {/* Meta Details */}
                <div className="bg-stone-900 border border-stone-800 rounded-2xl p-6 space-y-6">
                  <h3 className="text-[10px] font-black text-stone-500 uppercase tracking-[0.2em] border-b border-stone-800 pb-3">Finding Meta</h3>
                  
                  <div className="space-y-4">
                    <div>
                      <p className="text-[10px] text-stone-500 uppercase font-bold tracking-widest mb-1">First Detected</p>
                      <p className="text-xs text-stone-300 font-mono">{new Date(selectedFinding.first_seen || '').toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-stone-500 uppercase font-bold tracking-widest mb-1">Last Observed</p>
                      <p className="text-xs text-stone-300 font-mono">{new Date(selectedFinding.last_seen || '').toLocaleString()}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-stone-500 uppercase font-bold tracking-widest mb-1">Total Occurrences</p>
                      <p className="text-xs text-stone-300 font-mono">{selectedFinding.total_occurrences}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-stone-500 uppercase font-bold tracking-widest mb-1">Fingerprint</p>
                      <p className="text-[10px] text-stone-600 font-mono truncate">{selectedFinding.fingerprint}</p>
                    </div>
                  </div>
                </div>

                {/* Remediation Protocol */}
                <div className="bg-emerald-950/10 border border-emerald-800/30 rounded-2xl p-6 space-y-4">
                  <h3 className="text-[10px] font-black text-emerald-500 uppercase tracking-widest">Remediation Protocol</h3>
                  <p className="text-xs text-stone-300 leading-relaxed whitespace-pre-line font-mono">
                    {selectedFinding.remediation}
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center space-y-6 text-stone-700">
            <div className="p-8 bg-stone-900 rounded-full border border-stone-800">
              <ShieldAlert className="w-16 h-16" />
            </div>
            <div className="text-center space-y-2">
              <p className="text-lg font-black uppercase tracking-widest">Investigation Idle</p>
              <p className="text-xs font-mono">Select a finding from the deck to begin analysis.</p>
            </div>
          </div>
        )}
      </div>

      {/* Modal 1: One-Click GitHub Issue Creator */}
      {showIssueModal && selectedFinding && (
        <div className="fixed inset-0 bg-stone-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-stone-900 border border-stone-800 rounded-3xl max-w-2xl w-full p-6 space-y-6 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-stone-800 pb-4">
              <div className="flex items-center space-x-2.5">
                <Github className="w-5 h-5 text-white" />
                <h3 className="text-sm font-bold text-stone-100">Draft GitHub Security Issue</h3>
              </div>
              <button onClick={() => setShowIssueModal(false)} className="text-stone-500 hover:text-stone-300">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">Issue Title</label>
                <input
                  type="text"
                  readOnly
                  value={`[SECURITY] Credentials Exposed: ${selectedFinding.rule_name} in ${selectedFinding.primary_file}`}
                  className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">Markdown Payload Preview</label>
                <textarea
                  readOnly
                  rows={8}
                  value={generateIssueMarkdown(selectedFinding)}
                  className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl p-3 text-xs text-stone-300 font-mono resize-none"
                />
              </div>
            </div>

            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generateIssueMarkdown(selectedFinding));
                  setCopiedIssue(true);
                  setTimeout(() => setCopiedIssue(false), 2000);
                }}
                className="w-full sm:w-auto px-4 py-2.5 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-xs font-bold border border-stone-700 flex items-center justify-center space-x-2 cursor-pointer"
              >
                {copiedIssue ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedIssue ? 'Copied Markdown!' : 'Copy Issue Body'}</span>
              </button>

              <button
                onClick={() => openGitHubIssueDirectly(selectedFinding)}
                className="w-full sm:w-auto px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-bold flex items-center justify-center space-x-2 cursor-pointer shadow-lg shadow-cyan-600/20"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open in GitHub Issues &rarr;</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 2: Automated Secret Revocation Advisor */}
      {showRevokeModal && selectedFinding && (
        <div className="fixed inset-0 bg-stone-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-stone-900 border border-stone-800 rounded-3xl max-w-xl w-full p-6 space-y-6 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-stone-800 pb-4">
              <div className="flex items-center space-x-2.5">
                <Key className="w-5 h-5 text-rose-400" />
                <h3 className="text-sm font-bold text-stone-100">Credential Revocation Advisor</h3>
              </div>
              <button onClick={() => setShowRevokeModal(false)} className="text-stone-500 hover:text-stone-300">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="p-4 bg-rose-950/20 border border-rose-900/40 rounded-2xl space-y-2">
                <p className="text-xs font-bold text-rose-400">Target Credential: {selectedFinding.rule_name}</p>
                <p className="text-xs text-stone-300 font-mono">Masked Value: {selectedFinding.masked_secret}</p>
              </div>

              <div className="space-y-2 text-xs text-stone-300 font-mono">
                <p className="font-bold text-stone-200">Standard Revocation Workflow:</p>
                <ol className="list-decimal pl-5 space-y-1.5 text-stone-400">
                  <li>Navigate to upstream management console (AWS IAM, GitHub Token Settings, Stripe Dashboard).</li>
                  <li>Locate key matching suffix <code className="text-cyan-400">{selectedFinding.masked_secret.slice(-6)}</code>.</li>
                  <li>Click <strong>Revoke / Invalidate immediately</strong>.</li>
                  <li>Reissue scoped replacement credential stored in AWS Secrets Manager or GitHub Actions Secrets.</li>
                </ol>
              </div>

              <div className="p-4 bg-stone-950 border border-stone-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-stone-400">Automated Revocation Verification Hook</span>
                  {revocationVerified ? (
                    <span className="text-[10px] font-mono text-emerald-400 font-bold flex items-center space-x-1">
                      <Check className="w-3.5 h-3.5" />
                      <span>Verified Revoked</span>
                    </span>
                  ) : null}
                </div>
                <button
                  onClick={handleSimulateRevocationCheck}
                  disabled={isVerifyingRevocation}
                  className="w-full py-2 bg-stone-800 hover:bg-stone-700 disabled:opacity-50 text-stone-200 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer flex items-center justify-center space-x-2"
                >
                  <RotateCcw className={`w-3.5 h-3.5 ${isVerifyingRevocation ? 'animate-spin text-cyan-400' : ''}`} />
                  <span>{isVerifyingRevocation ? 'Checking upstream endpoint...' : 'Simulate API Invalidation Verification'}</span>
                </button>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowRevokeModal(false)}
                className="px-5 py-2.5 bg-stone-800 hover:bg-stone-700 text-stone-200 rounded-xl text-xs font-bold border border-stone-700 cursor-pointer"
              >
                Close Advisor
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal 3: Formal Exception Management & Sign-off Dialog */}
      {showSignOffModal && selectedFinding && (
        <div className="fixed inset-0 bg-stone-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-stone-900 border border-stone-800 rounded-3xl max-w-xl w-full p-6 space-y-6 shadow-2xl animate-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-stone-800 pb-4">
              <div className="flex items-center space-x-2.5">
                <UserCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-stone-100">Sign-Off Governance Exception</h3>
              </div>
              <button onClick={() => setShowSignOffModal(false)} className="text-stone-500 hover:text-stone-300">
                <X className="w-4 h-4" />
              </button>
            </div>

            {signOffSuccess ? (
              <div className="py-8 text-center space-y-3 animate-in fade-in">
                <Check className="w-12 h-12 text-emerald-400 mx-auto" />
                <h4 className="text-base font-bold text-stone-100">Exception Digitally Signed & Logged</h4>
                <p className="text-xs text-stone-400 font-mono">Audit record registered in organization compliance logs.</p>
              </div>
            ) : (
              <form onSubmit={handleSignOffSubmit} className="space-y-4">
                <div>
                  <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">Target Status</label>
                  <select
                    value={signOffStatus}
                    onChange={(e) => setSignOffStatus(e.target.value)}
                    className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500"
                  >
                    <option value="False Positive">False Positive (Verified Test/Placeholder)</option>
                    <option value="Accepted Risk">Accepted Risk (Low Impact / Isolated Testbed)</option>
                    <option value="Resolved">Resolved (Rotated & Purged)</option>
                  </select>
                </div>

                <div>
                  <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">
                    Business Justification (Required for SOC2 / ISO compliance)
                  </label>
                  <textarea
                    required
                    rows={3}
                    placeholder="Describe why this credential does not represent a production vulnerability..."
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                    className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl p-3 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500 resize-none"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">Approver Digital Signature</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. Jane Doe (SecOps Lead)"
                      value={approverName}
                      onChange={(e) => setApproverName(e.target.value)}
                      className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-mono uppercase text-stone-500 font-bold">Review Expiration</label>
                    <select
                      value={expiryOption}
                      onChange={(e) => setExpiryOption(e.target.value)}
                      className="w-full mt-1 bg-stone-950 border border-stone-800 rounded-xl px-3 py-2 text-xs text-stone-200 font-mono focus:outline-none focus:border-cyan-500"
                    >
                      <option value="30_days">30 Days (Temporary)</option>
                      <option value="90_days">90 Days (Quarterly Audit)</option>
                      <option value="permanent">Permanent Exception</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center justify-end space-x-3 pt-4 border-t border-stone-800">
                  <button
                    type="button"
                    onClick={() => setShowSignOffModal(false)}
                    className="px-4 py-2 bg-stone-800 hover:bg-stone-700 text-stone-300 rounded-xl text-xs font-bold border border-stone-700 cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSubmittingSignOff || !justification.trim()}
                    className="px-6 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all shadow-md shadow-cyan-600/20 cursor-pointer"
                  >
                    {isSubmittingSignOff ? 'Logging Sign-Off...' : 'Submit Digital Sign-Off'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
