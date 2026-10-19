import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { fetchTimeline } from '../api/client';
import { AnalysisNav } from '../components/AnalysisNav';
import { Clock, Filter } from 'lucide-react';

export const TimelinePage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter
  const [typeFilter, setTypeFilter] = useState<string>('all');

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        const res = await fetchTimeline(id);
        setEvents(res || []);
        setError(null);
      } catch (err: any) {
        setError(err?.error?.message || 'Failed to load timeline events');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  const eventTypes = ['all', ...Array.from(new Set(events.map((e) => e.event_type).filter(Boolean)))];

  const filteredEvents = typeFilter === 'all'
    ? events
    : events.filter((e) => e.event_type === typeFilter);

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
      <AnalysisNav />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Clock className="w-6 h-6 text-sky-400" /> Capture Events Chronology
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Chronological sequence of IKE handshakes, Rekey transitions, ESP sequence gaps, and alerts.
          </p>
        </div>

        {/* Filter */}
        {eventTypes.length > 2 && (
          <div className="flex items-center gap-1.5 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span>Type:</span>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-transparent text-white font-medium focus:outline-none cursor-pointer"
            >
              {eventTypes.map((t) => (
                <option key={t} value={t} className="bg-slate-800">
                  {t}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {loading ? (
        <div className="p-16 text-center text-slate-400">Loading timeline...</div>
      ) : error ? (
        <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm">{error}</div>
      ) : filteredEvents.length === 0 ? (
        <div className="p-16 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <Clock className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-slate-300">No Events in Timeline</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            No events were recorded for the selected timeline filter.
          </p>
        </div>
      ) : (
        <div className="relative border-l border-slate-800 ml-4 sm:ml-6 space-y-6 pb-6">
          {filteredEvents.map((ev, idx) => {
            const isWarn = ev.severity === 'Warning' || ev.event_type?.includes('GAP') || ev.event_type?.includes('FAIL');
            const isErr = ev.severity === 'Error' || ev.event_type?.includes('ERROR');

            const dotColor = isErr
              ? 'bg-red-500 border-red-900'
              : isWarn
              ? 'bg-amber-500 border-amber-900'
              : 'bg-sky-500 border-sky-900';

            const relTime = typeof ev.relative_time === 'number'
              ? `+${ev.relative_time.toFixed(3)}s`
              : ev.timestamp
              ? new Date(ev.timestamp * 1000).toISOString().slice(11, 23)
              : `#${idx + 1}`;

            return (
              <div key={idx} className="relative pl-6 sm:pl-8 group">
                {/* Timeline node circle */}
                <div
                  className={`absolute -left-2 top-2 w-4 h-4 rounded-full border-2 ${dotColor} transition-transform group-hover:scale-125`}
                />

                <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 p-4 rounded-xl shadow-md space-y-2 transition-colors">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 text-sky-400 border border-slate-800 font-bold">
                        {ev.event_type || 'EVENT'}
                      </span>
                      {ev.src_ip && ev.dst_ip && (
                        <span className="text-xs font-mono text-slate-400">
                          {ev.src_ip} → {ev.dst_ip}
                        </span>
                      )}
                    </div>

                    <span className="text-xs font-mono text-slate-500">{relTime}</span>
                  </div>

                  <p className="text-xs text-slate-200 font-medium">
                    {ev.summary || ev.description || 'Event recorded'}
                  </p>

                  {ev.details && Object.keys(ev.details).length > 0 && (
                    <div className="p-2.5 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-400 border border-slate-800/80 overflow-x-auto">
                      {JSON.stringify(ev.details, null, 2)}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
