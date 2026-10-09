import React, { useState, useEffect } from 'react';
import {
  Network,
  ArrowRight,
  ShieldAlert,
  Clock,
  ExternalLink,
  ChevronRight,
  GitBranch,
  GitCommit,
  LayoutGrid
} from 'lucide-react';
import { Finding } from '../types';

interface ExposureIntelligenceViewProps {
  findings: Finding[];
  initialFingerprint?: string;
  onFetchExposure: (fingerprint: string) => Promise<any>;
}

export const ExposureIntelligenceView: React.FC<ExposureIntelligenceViewProps> = ({
  findings,
  initialFingerprint,
  onFetchExposure
}) => {
  const [selectedFingerprint, setSelectedFingerprint] = useState(initialFingerprint || findings[0]?.fingerprint || '');
  const [exposureData, setExposureData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (selectedFingerprint) {
      loadExposure();
    }
  }, [selectedFingerprint]);

  const loadExposure = async () => {
    setIsLoading(true);
    try {
      const data = await onFetchExposure(selectedFingerprint);
      setExposureData(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  const uniqueFingerprints = Array.from(new Set(findings.map(f => f.fingerprint)))
    .map(fp => findings.find(f => f.fingerprint === fp)!);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8 animate-in fade-in duration-500">
      <div className="border-b border-stone-800 pb-8">
        <h1 className="text-2xl font-black text-stone-100 tracking-tight flex items-center space-x-3">
          <Network className="w-7 h-7 text-cyan-500" />
          <span>Secret Exposure Intelligence</span>
        </h1>
        <p className="text-xs text-stone-500 font-mono mt-1 uppercase tracking-widest">
           Tracing credential lifecycle & lateral spread paths
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Selector */}
        <div className="lg:col-span-1 space-y-4">
           <h2 className="text-[10px] font-black text-stone-500 uppercase tracking-widest ml-1">Select Fingerprint</h2>
           <div className="bg-stone-900 border border-stone-800 rounded-2xl overflow-hidden divide-y divide-stone-800 shadow-xl">
             {uniqueFingerprints.map((f) => (
               <button
                 key={f.id}
                 onClick={() => setSelectedFingerprint(f.fingerprint)}
                 className={`w-full p-4 text-left transition-all hover:bg-stone-800/50 ${selectedFingerprint === f.fingerprint ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''}`}
               >
                 <p className="text-xs font-bold text-stone-200 truncate">{f.rule_name}</p>
                 <p className="text-[9px] text-stone-500 font-mono mt-1 truncate uppercase">{f.masked_secret}</p>
               </button>
             ))}
             {uniqueFingerprints.length === 0 && (
               <div className="p-8 text-center text-stone-700 text-xs font-mono italic">No data.</div>
             )}
           </div>
        </div>

        {/* Intelligence View */}
        <div className="lg:col-span-3 space-y-8">
          {isLoading ? (
            <div className="py-32 flex flex-col items-center justify-center space-y-4">
              <Network className="w-8 h-8 text-cyan-500 animate-pulse" />
              <p className="text-stone-500 font-mono text-xs uppercase">Mapping exposure network...</p>
            </div>
          ) : exposureData ? (
            <div className="space-y-8 animate-in fade-in slide-in-from-right-4 duration-500">
               {/* Summary Card */}
               <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 shadow-2xl relative overflow-hidden">
                 <div className="absolute top-0 right-0 p-8">
                   <ShieldAlert className="w-12 h-12 text-rose-500/20" />
                 </div>
                 <div className="space-y-6">
                    <div className="flex items-center space-x-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${exposureData.severity === 'CRITICAL' ? 'bg-rose-500/10 text-rose-400' : 'bg-amber-500/10 text-amber-400'}`}>
                        {exposureData.severity}
                      </span>
                      <h3 className="text-xl font-black text-stone-100 uppercase tracking-tight">{exposureData.ruleName}</h3>
                    </div>
                    
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-stone-950/50 rounded-2xl p-4 border border-stone-800">
                        <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Occurrences</p>
                        <p className="text-xl font-black text-stone-200 mt-1">{exposureData.totalOccurrences}</p>
                      </div>
                      <div className="bg-stone-950/50 rounded-2xl p-4 border border-stone-800">
                        <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Confidence</p>
                        <p className="text-xl font-black text-stone-200 mt-1">{Math.round(exposureData.confidence * 100)}%</p>
                      </div>
                      <div className="bg-stone-950/50 rounded-2xl p-4 border border-stone-800">
                        <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Exposure</p>
                        <p className={`text-xl font-black mt-1 ${exposureData.isCurrentlyPresent ? 'text-rose-400' : 'text-cyan-400'}`}>
                          {exposureData.isCurrentlyPresent ? 'Active' : 'Purged'}
                        </p>
                      </div>
                      <div className="bg-stone-950/50 rounded-2xl p-4 border border-stone-800">
                        <p className="text-[9px] text-stone-500 uppercase font-black tracking-widest">Spread</p>
                        <p className="text-xl font-black text-stone-200 mt-1">1 Repo</p>
                      </div>
                    </div>
                 </div>
               </div>

               <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                 {/* Exposure Timeline */}
                 <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 space-y-6">
                    <h3 className="text-xs font-black text-stone-400 uppercase tracking-widest flex items-center space-x-2">
                      <Clock className="w-4 h-4 text-cyan-500" />
                      <span>Exposure Timeline</span>
                    </h3>
                    <div className="relative pl-6 border-l border-stone-800 space-y-8">
                      {exposureData.timeline_events?.map((evt: any, i: number) => (
                        <div key={i} className="relative">
                          <div className="absolute -left-[27px] top-1 w-3 h-3 rounded-full bg-cyan-500 shadow-[0_0_10px_rgba(6,182,212,0.5)]"></div>
                          <div className="space-y-1">
                            <p className="text-[10px] text-stone-500 font-mono font-bold uppercase">{evt.date}</p>
                            <p className="text-sm font-bold text-stone-200">{evt.title}</p>
                            <p className="text-xs text-stone-400 leading-relaxed italic">"{evt.description}"</p>
                          </div>
                        </div>
                      ))}
                      {(!exposureData.timeline_events || exposureData.timeline_events.length === 0) && (
                        <div className="relative">
                           <div className="absolute -left-[27px] top-1 w-3 h-3 rounded-full bg-stone-700"></div>
                           <p className="text-xs text-stone-600 font-mono italic">No historical events recorded.</p>
                        </div>
                      )}
                    </div>
                 </div>

                 {/* Relationship Graph (Simplified Visual Representation) */}
                 <div className="bg-stone-900 border border-stone-800 rounded-3xl p-8 space-y-6 flex flex-col">
                    <h3 className="text-xs font-black text-stone-400 uppercase tracking-widest flex items-center space-x-2">
                      <LayoutGrid className="w-4 h-4 text-emerald-500" />
                      <span>Correlation Graph</span>
                    </h3>
                    <div className="flex-1 flex flex-col items-center justify-center space-y-8 relative overflow-hidden">
                       <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-cyan-500/5 via-transparent to-transparent"></div>
                       
                       <div className="p-4 bg-rose-950/20 border border-rose-500/50 rounded-2xl z-10 text-center shadow-2xl">
                          <ShieldAlert className="w-6 h-6 text-rose-500 mx-auto mb-2" />
                          <p className="text-[10px] font-black text-stone-200 uppercase tracking-widest">{exposureData.ruleName}</p>
                          <p className="text-[9px] text-stone-500 font-mono mt-1">{exposureData.maskedSecret}</p>
                       </div>

                       <div className="h-12 w-px bg-stone-800 z-10"></div>

                       <div className="flex space-x-12 z-10">
                          <div className="p-4 bg-stone-950 border border-stone-800 rounded-2xl text-center group cursor-pointer hover:border-cyan-500/50 transition-colors">
                            <GitBranch className="w-5 h-5 text-cyan-400 mx-auto mb-2" />
                            <p className="text-[9px] font-black text-stone-300 uppercase tracking-widest">{exposureData.repositoryName}</p>
                          </div>
                          <div className="p-4 bg-stone-950 border border-stone-800 rounded-2xl text-center">
                            <GitCommit className="w-5 h-5 text-stone-500 mx-auto mb-2" />
                            <p className="text-[9px] font-black text-stone-500 uppercase tracking-widest">#8f31a2c</p>
                          </div>
                       </div>
                    </div>
                 </div>
               </div>
            </div>
          ) : (
             <div className="py-32 flex flex-col items-center justify-center space-y-6 text-stone-800">
              <div className="p-12 bg-stone-900 rounded-full border border-stone-800">
                <Network className="w-16 h-16" />
              </div>
              <div className="text-center space-y-2">
                <p className="text-lg font-black uppercase tracking-widest">Investigation Idle</p>
                <p className="text-xs font-mono">Select a fingerprint to visualize its exposure network.</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
