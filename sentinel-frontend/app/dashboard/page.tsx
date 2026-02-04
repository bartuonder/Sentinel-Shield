'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';
import {
  Shield, AlertTriangle, Activity, Ban, LogOut,
  Terminal, Copy, CheckCircle2, Server, Eye
} from 'lucide-react';

export default function DashboardPage() {
  const router = useRouter();

  const [user, setUser] = useState<any>(null);
  const [stats, setStats] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [bans, setBans] = useState<any[]>([]);

  const [activeTab, setActiveTab] = useState('logs');
  const [copied, setCopied] = useState(false);
  const [revealKey, setRevealKey] = useState(false);

  const fetchData = async () => {
    try {
      const [userRes, statsRes, logsRes, bansRes] = await Promise.all([
        api.get('/dashboard/me'),
        api.get('/dashboard/stats'),
        api.get('/dashboard/logs'),
        api.get('/dashboard/bans')
      ]);

      setUser(userRes.data);
      setStats(statsRes.data);
      setLogs(logsRes.data);
      setBans(bansRes.data);
    } catch (error) {
      console.error("Dashboard veri hatası (Kullanıcı görmemeli)", error);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
    } else {
      fetchData();
      const interval = setInterval(fetchData, 5000);
      return () => clearInterval(interval);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  const copyApiKey = () => {
    if (!user?.api_key) return;

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(user.api_key)
        .then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        })
        .catch(() => {

          fallbackCopyTextToClipboard(user.api_key);
        });
    } else {

      fallbackCopyTextToClipboard(user.api_key);
    }
  };

  const fallbackCopyTextToClipboard = (text: string) => {
    const textArea = document.createElement("textarea");
    textArea.value = text;

    textArea.style.position = "fixed";
    textArea.style.left = "-9999px";
    textArea.style.top = "0";

    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
      document.execCommand('copy');
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Kopyalama başarısız', err);
      alert('Kopyalanamadı, lütfen manuel seçiniz.');
    }

    document.body.removeChild(textArea);
  };

  const calculateScore = () => {
    if (!stats || stats.total_requests === 0) return 100;
    const attackRatio = stats.blocked_attacks / stats.total_requests;
    return Math.max(0, Math.round(100 - (attackRatio * 50)));
  };

  if (!user) return <div className="min-h-screen bg-black text-white flex items-center justify-center font-mono animate-pulse">SYSTEM_CONNECTING...</div>;

  return (
    <div className="min-h-screen bg-black text-gray-200 font-sans flex flex-col md:flex-row">

      {/* --- SIDEBAR --- */}
      <aside className="w-full md:w-64 border-b md:border-b-0 md:border-r border-gray-800 bg-gray-950 p-6 flex flex-col">
        <div className="flex items-center gap-3 mb-8">
          <div className="bg-red-900/20 p-2 rounded-lg">
            <Shield className="h-6 w-6 text-red-600" />
          </div>
          <h1 className="text-xl font-bold text-white tracking-widest">SENTINEL</h1>
        </div>

        <nav className="space-y-2 flex-1">
          <button
            onClick={() => setActiveTab('logs')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeTab === 'logs' ? 'bg-red-900/10 text-red-400 border border-red-900/20' : 'hover:bg-gray-900 text-gray-400'}`}
          >
            <Activity size={18} /> Aktivite Logları
          </button>
          <button
            onClick={() => setActiveTab('bans')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeTab === 'bans' ? 'bg-red-900/10 text-red-400 border border-red-900/20' : 'hover:bg-gray-900 text-gray-400'}`}
          >
            <Ban size={18} /> Banlı IP Listesi
          </button>
        </nav>

        <div className="mt-8 pt-6 border-t border-gray-800">
          <div className="bg-gray-900/50 p-3 rounded-lg mb-4 border border-gray-800 flex items-center gap-3">
            <div className="h-8 w-8 rounded-full bg-red-900/30 flex items-center justify-center text-red-500 font-bold">
                {user.full_name?.charAt(0)}
            </div>
            <div className="overflow-hidden">
                <div className="text-xs text-gray-500">Kullanıcı</div>
                <div className="font-medium text-white text-sm truncate">{user.full_name}</div>
            </div>
          </div>
          <button onClick={handleLogout} className="flex items-center gap-2 text-sm text-gray-500 hover:text-red-400 transition-colors w-full px-2">
            <LogOut size={16} /> Güvenli Çıkış
          </button>
        </div>
      </aside>

      {/* --- ANA İÇERİK --- */}
      <main className="flex-1 p-4 md:p-8 overflow-y-auto">

        {/* ÜST BİLGİ & API KEY */}
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-8 gap-4">
          <div>
            <h2 className="text-2xl font-bold text-white mb-1">Güvenlik Paneli</h2>
            <div className="flex items-center gap-2 text-sm">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
                </span>
                <span className="text-green-500 font-mono">SYSTEM ONLINE</span>
            </div>
          </div>

          {/* API Key Kartı */}
          <div className="bg-gray-900/50 border border-gray-800 p-3 rounded-xl flex items-center gap-4 w-full lg:w-auto">
            <div className="bg-gray-800 p-2 rounded-lg">
              <Server size={20} className="text-blue-400" />
            </div>
            <div className="flex-1">
              <div className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">Secret API Key</div>
              <div className="font-mono text-sm text-white flex items-center gap-2">
                {revealKey ? user.api_key : `${user.api_key?.substring(0, 8)}••••••••••••••••`}
                <button onClick={() => setRevealKey(!revealKey)} className="text-gray-500 hover:text-white ml-2">
                    <Eye size={14} />
                </button>
              </div>
            </div>
            <button onClick={copyApiKey} className="p-2 hover:bg-gray-800 rounded-md transition-colors text-gray-400 hover:text-white border border-gray-700">
              {copied ? <CheckCircle2 size={18} className="text-green-500" /> : <Copy size={18} />}
            </button>
          </div>
        </div>

        {/* İSTATİSTİK KARTLARI */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
                <div className="flex justify-between mb-2">
                    <div className="text-gray-500 text-xs uppercase font-bold">Toplam İstek</div>
                    <Activity size={18} className="text-blue-500" />
                </div>
                <div className="text-3xl font-bold text-white">{stats?.total_requests || 0}</div>
            </div>

            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl border-l-4 border-l-red-600">
                <div className="flex justify-between mb-2">
                    <div className="text-gray-500 text-xs uppercase font-bold">Engellenen</div>
                    <Shield size={18} className="text-red-500" />
                </div>
                <div className="text-3xl font-bold text-white">{stats?.blocked_attacks || 0}</div>
            </div>

            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
                <div className="flex justify-between mb-2">
                    <div className="text-gray-500 text-xs uppercase font-bold">Banlanan IP</div>
                    <Ban size={18} className="text-orange-500" />
                </div>
                <div className="text-3xl font-bold text-white">{stats?.global_banned_ips || 0}</div>
            </div>

            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
                <div className="flex justify-between mb-2">
                    <div className="text-gray-500 text-xs uppercase font-bold">Güvenlik Skoru</div>
                    <CheckCircle2 size={18} className="text-green-500" />
                </div>
                <div className="flex items-end gap-2">
                    <div className="text-3xl font-bold text-white">%{calculateScore()}</div>
                </div>
            </div>
        </div>

        {/* TABLOLAR */}
        <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden min-h-[400px] shadow-2xl">

          {/* LOGLAR TABLOSU */}
          {activeTab === 'logs' && (
            <div>
              <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2 bg-gray-900/30">
                <Terminal size={18} className="text-gray-400" />
                <h3 className="font-bold text-white text-sm">Canlı Saldırı Trafiği</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-400">
                  <thead className="bg-gray-900 text-gray-500 uppercase text-xs font-semibold">
                    <tr>
                      <th className="px-6 py-3">Zaman</th>
                      <th className="px-6 py-3">IP Adresi</th>
                      <th className="px-6 py-3">Modül</th>
                      <th className="px-6 py-3">Mesaj</th>
                      <th className="px-6 py-3">Durum</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {logs.map((log, i) => (
                      <tr key={i} className="hover:bg-gray-900/50 transition-colors group">
                        <td className="px-6 py-4 font-mono text-xs text-gray-500">
                            {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-6 py-4 font-mono text-xs text-blue-400 group-hover:text-blue-300">{log.ip_address}</td>
                        <td className="px-6 py-4">
                            <span className="bg-gray-800 px-2 py-1 rounded text-[10px] text-gray-300 border border-gray-700 uppercase tracking-wide">
                                {log.scanner_name}
                            </span>
                        </td>
                        <td className="px-6 py-4 max-w-xs truncate text-gray-300 font-mono text-xs" title={log.request_text}>
                            {log.request_text}
                        </td>
                        <td className="px-6 py-4">
                          {log.is_allowed ? (
                             <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-green-950 text-green-400 border border-green-900/30">
                                ALLOWED
                             </span>
                          ) : (
                             <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-500 border border-red-900/30">
                                BLOCKED
                             </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {logs.length === 0 && (
                    <div className="p-12 text-center text-gray-600 flex flex-col items-center">
                        <Activity size={32} className="mb-2 opacity-50" />
                        Henüz trafik verisi yok.
                    </div>
                )}
              </div>
            </div>
          )}

          {/* BAN LİSTESİ */}
          {activeTab === 'bans' && (
            <div>
              <div className="px-6 py-4 border-b border-gray-800 flex items-center gap-2 bg-gray-900/30">
                <Ban size={18} className="text-red-500" />
                <h3 className="font-bold text-white text-sm">Yasaklı IP Listesi (Blacklist)</h3>
              </div>
              <div className="p-6">
                {bans.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {bans.map((ban, i) => (
                      <div key={i} className="bg-red-950/10 border border-red-900/30 p-4 rounded-lg flex items-center justify-between group hover:bg-red-950/20 transition-colors">
                        <div>
                          <div className="font-mono text-white font-bold tracking-wide">{ban.ip_address}</div>
                          <div className="text-xs text-red-400 mt-1 flex items-center gap-1">
                            <AlertTriangle size={10} /> {ban.reason}
                          </div>
                          <div className="text-xs text-gray-600 mt-1">
                             {new Date(ban.banned_at).toLocaleDateString()}
                          </div>
                        </div>
                        <Ban size={20} className="text-red-900 group-hover:text-red-600 transition-colors" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-16">
                    <div className="bg-gray-900 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4 border border-gray-800">
                        <Shield size={32} className="text-green-500" />
                    </div>
                    <h4 className="text-white font-medium mb-1">Liste Temiz</h4>
                    <p className="text-gray-500 text-sm">Şu an aktif bir ban kaydı bulunmuyor.</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}