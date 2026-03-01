# 🛡️ Sentinel-Shield: Enterprise AI Security Gateway & SaaS Platform

**Sentinel-Shield**, modern web uygulamaları ve Büyük Dil Modelleri (LLM) entegrasyonları için geliştirilmiş, yüksek performanslı ve bulut tabanlı bir **Security-as-a-Service (SaaS)** çözümüdür. Geliştiriciler, platform üzerinden aldıkları API Key ile tüm trafiklerini Sentinel-Shield üzerinden geçirerek uçtan uca koruma sağlarlar.

---

## 🚀 Temel Fonksiyonlar ve Güvenlik Filtreleme Mantığı

Sistem, gelen her istemi (request) üç temel aşamadan geçirir:

### 1. Tehdit Engelleme (Blocking)
Gelen mesajlar semantik ve imza tabanlı analizlerden geçer.
* **LLM Guard:** Yapay zekayı kandırmaya yönelik sinsi "Jailbreak" ve "Prompt Injection" denemeleri OpenAI GPT-4o-mini ile analiz edilerek anında engellenir.
* **Klasik Enjeksiyon:** SQLi, XSS ve diğer web tabanlı saldırı vektörleri sistem tarafından tespit edildiği an istek **BLOCKED** durumuna düşürülür.

### 2. Veri Anonimleştirme (PII Sanitization)
Mesaj temizse ancak hassas veri içeriyorsa devreye girer:
* **Microsoft Presidio:** `pii_scanner.py` modülü, hem açık hem de gizli kalmış hassas verileri (TCKN, IBAN, Email, Telefon) **PresidioAnalyzer** ile tespit eder.
* **Maskeleme:** Tespit edilen veriler `[TR_TCKN REDACTED]` gibi etiketlerle sansürlenerek hedef LLM'e güvenli bir şekilde iletilir.

### 3. Akıllı Ban ve IP Yönetimi (5-Strike Rule)
Saldırgan IP adreslerini izole etmek için hibrit bir mantık kullanılır:
* **Kullanıcı Bazlı Ban:** Bir IP adresi, belirli bir API Key üzerinden **5 kez** kural ihlali yaparsa, o kullanıcı için kalıcı olarak banlanır.
* **Sistem Koruma (Rate Limiter):** Kendi backend altyapımızı korumak için, çok yüksek frekansta istek atan IP'ler Redis üzerinde kısa süreli (TTL bazlı) bloklanarak sistem yükü dengelenir.

---

## 🏗️ Mimari ve Cloud Altyapısı



### Cloud Katmanı
* **Hosting:** **AWS EC2** üzerinde Dockerize edilmiş mimari.
* **Giriş Katmanı:** **Nginx** ters proxy (Reverse Proxy) olarak konumlandırılmıştır.
* **Veritabanı:** **AWS RDS (PostgreSQL)** kalıcı loglar ve kullanıcı verileri için kullanılır.
* **Güvenlik Protokolü:** EC2 ve RDS arasındaki veri trafiği, en düşük yetki ilkesine dayalı **AWS Security Groups** ile izole edilmiştir.

### Veri ve Cache Stratejisi (Upstash Redis)
Redis üzerinde performans için 3 temel veri tipi tutulur:
1.  **Rate Limit Verisi:** Backend'i aşırı yükten korumak için IP bazlı sayaçlar.
2.  **Ban Status:** Hız optimizasyonu için banlı IP'lerin sorgulanması Redis üzerinden yapılır.
3.  **Hashed Queries:** Performansı artırmak ve mükerrer istek maliyetini düşürmek için 24 saatlik sorular hashlenerel saklanır.

---

## 🛠️ Teknoloji Yığını

* **Backend:** FastAPI, Starlette, Pydantic (v2), SQLAlchemy (Async).
* **Frontend:** Next.js (Dashboard & Auth Management).
* **Veri Güvenliği:** Microsoft Presidio Analyzer.
* **Authentication:** JWT (Stateless Auth).
* **Altyapı:** Docker & Docker-Compose.

---

## ⚙️ Kurulum (Configuration)

Ana dizinde bir `.env` dosyası oluşturun ve aşağıdaki şablonu kendi cloud bilgilerinizle doldurun:

```env

OpenAI API Settings:
API_KEY=your_openai_api_key

JWT & Core Security:
SECRET_KEY=kendi_guvenli_anahtariniz
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

Cloud Infrastructure (AWS & Upstash):
REDIS_URL=rediss://default:password@endpoint:6379
DATABASE_URL=postgresql+asyncpg://user:password@rds_endpoint:5432/dbname

Connection Settings:
NEXT_PUBLIC_API_URL=http://ec2_ip_adresiniz/api/v1

Docker ile Başlatma:
docker-compose up --build -d

Geliştirici: Bartu Önder - Software Engineering Student
Vizyon: Backend/Software Engineering - AI Security
