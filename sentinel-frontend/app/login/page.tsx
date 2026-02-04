'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { Shield, Lock, User, KeyRound, AlertCircle } from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const [isLogin, setIsLogin] = useState(true);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // --- DÜZELTME: Email Format Kontrolü ---
  const validateEmail = (email: string) => {
    return String(email)
      .toLowerCase()
      .match(
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
      );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // --- DÜZELTME: Client-Side Validation ---
    if (!validateEmail(email)) {
        setError('Lütfen geçerli bir e-posta adresi giriniz.');
        setLoading(false);
        return;
    }

    if (password.length < 4) {
        setError('Şifre en az 4 karakter olmalıdır.');
        setLoading(false);
        return;
    }

    try {
      if (isLogin) {

        const formData = new FormData();
        formData.append('username', email);
        formData.append('password', password);

        // --- DÜZELTME: 401 Hatasını Yakalama ---
        try {
            const res = await api.post('/auth/login', formData, {
                headers: { 'Content-Type': 'multipart/form-data' }
            });
            localStorage.setItem('token', res.data.access_token);
            router.push('/dashboard');
        } catch (authError: any) {
            if (authError.response?.status === 401) {
                throw new Error("E-posta veya şifre hatalı!");
            }
            throw authError; // Diğer hataları dışarı fırlat
        }

      } else {
        // Kayıt Olma İşlemi
        await api.post('/auth/signup', {
            email: email,
            password: password,
            full_name: fullName
        });
        alert('Kayıt başarılı! Şimdi giriş yapabilirsiniz.');
        setIsLogin(true);
      }
    } catch (err: any) {
      console.error(err);
      // Hata mesajını düzgün göster
      const msg = err.message || err.response?.data?.detail || 'Sunucu hatası oluştu.';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-black text-white p-4 font-sans">
      {/* Arka Plan Efekti */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-red-900/20 via-black to-black z-0 pointer-events-none"></div>

      <div className="w-full max-w-md space-y-8 rounded-2xl border border-gray-800 bg-gray-950/90 backdrop-blur-sm p-8 shadow-2xl relative z-10">

        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-red-900/20 mb-4 animate-pulse">
            <Shield className="h-8 w-8 text-red-600" />
          </div>
          <h2 className="text-3xl font-bold tracking-tight text-white">Sentinel Shield</h2>
          <p className="mt-2 text-sm text-gray-400">
            {isLogin ? 'Güvenlik Paneline Giriş' : 'Yeni Hesap Oluştur'}
          </p>
        </div>

        <form className="mt-8 space-y-5" onSubmit={handleSubmit}>

          {!isLogin && (
            <div className="relative group">
              <User className="absolute left-3 top-3 h-5 w-5 text-gray-500 group-focus-within:text-red-500 transition-colors" />
              <input
                type="text"
                required
                placeholder="Ad Soyad"
                className="w-full rounded-lg border border-gray-800 bg-gray-900/50 py-3 pl-10 text-white placeholder-gray-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-all"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
              />
            </div>
          )}

          <div className="relative group">
            <KeyRound className="absolute left-3 top-3 h-5 w-5 text-gray-500 group-focus-within:text-red-500 transition-colors" />
            <input
              type="email"
              required
              placeholder="Email Adresi"
              className="w-full rounded-lg border border-gray-800 bg-gray-900/50 py-3 pl-10 text-white placeholder-gray-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-all"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="relative group">
            <Lock className="absolute left-3 top-3 h-5 w-5 text-gray-500 group-focus-within:text-red-500 transition-colors" />
            <input
              type="password"
              required
              placeholder="Şifre"
              className="w-full rounded-lg border border-gray-800 bg-gray-900/50 py-3 pl-10 text-white placeholder-gray-600 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 transition-all"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-md bg-red-950/50 p-3 text-sm text-red-400 border border-red-900/50 animate-bounce">
              <AlertCircle size={16} />
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-red-700 py-3 text-sm font-bold text-white shadow-lg hover:bg-red-600 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-900 disabled:opacity-50 transition-all transform active:scale-95"
          >
            {loading ? 'İşleniyor...' : (isLogin ? 'Giriş Yap' : 'Kayıt Ol')}
          </button>
        </form>

        <div className="text-center pt-2">
          <button
            onClick={() => { setIsLogin(!isLogin); setError(''); }}
            className="text-sm font-medium text-gray-500 hover:text-white transition-colors"
          >
            {isLogin ? 'Hesabın yok mu? Kayıt Ol' : 'Zaten hesabın var mı? Giriş Yap'}
          </button>
        </div>
      </div>
    </div>
  );
}