🛡️ Sentinel-Shield: Enterprise AI Security Gateway & SaaS Platform

Sentinel-Shield, modern web uygulamaları ve Büyük Dil Modelleri (LLM) için geliştirilmiş, yüksek performanslı bir Security-as-a-Service (SaaS) çözümüdür. Geliştiriciler, platform üzerinden aldıkları API Key ile isteklerini Sentinel-Shield üzerinden geçirerek sistemlerini hem klasik siber tehditlere hem de gelişmiş AI manipülasyonlarına karşı koruma altına alırlar.

🚀 Temel Fonksiyonlar ve Güvenlik Mantığı

1. PII Sanitization (Veri Sızıntısı Önleme): Sistem, pii_scanner.py modülü içerisinde Microsoft Presidio (PresidioAnalyzer) kütüphanesini kullanarak istemler içindeki hassas verileri (TCKN, IBAN, Email, Telefon vb.) gerçek zamanlı olarak tespit eder. Tespit edilen veriler, hedef LLM'e ulaşmadan önce maskelenerek veri gizliliği (DLP) sağlanır.
2. Akıllı Ban ve IP Yönetimi (5-Strike Rule): Saldırgan IP adreslerini yönetmek için hibrit bir yapı kullanılır:
Ban Mantığı: Bir saldırgan IP, belirli bir API Key üzerinden 5 kez güvenlik kuralı ihlali yaparsa, o kullanıcı/API Key için otomatik olarak banlanır.
Hibrit Depolama: Banlanan IP'ler, doğrulama hızı için Upstash Redis'te, geçmişe dönük analiz ve dashboard gösterimi için AWS RDS (PostgreSQL) veritabanında saklanır.
3. Katmanlı Rate LimitingSistemin sürekliliğini korumak amacıyla iki aşamalı sınırlama uygulanır:Sistem Koruması: Backend'e yönelik aşırı yüklenmeleri engellemek için genel rate limiter devreye girer.
Geçici Bloklama: Çok hızlı istek atarak sistemi manipüle etmeye çalışan IP'ler, Redis üzerinde kısa süreli (TTL ile) banlanarak izole edilir.
4. Semantik Güvenlik (LLM Guard)Yapay zekayı manipüle etmeyi amaçlayan "Jailbreak" ve "Prompt Injection" saldırıları, OpenAI GPT-4o-mini kullanılarak semantik analizden geçirilir ve zararlı istemler daha işleme alınmadan engellenir.

🏗️ Teknoloji Yığını ve AltyapıBileşenKullanılan Teknoloji

Backend: FastAPI, Starlette, Pydantic(v2)
Veritabanı (ORM): SQLAlchemy (Async) & AWS RDS PostgreSQL
Önbellek (Cache): Upstash Redis (Cloud)
Security Engine: Microsoft Presidio (PresidioAnalyzer)
AI Analiz: OpenAI GPT-4o-mini
Deployment: AWS EC2 & Docker-Compose
Frontend: Next.js

🛠️ Mimari Kararlar

Monolitik Yapı: Hızlı geliştirme ve düşük gecikme süresi (low latency) için monolitik mimari tercih edilmiştir.
Redis Hashing: Mükerrer istekleri engellemek ve performansı artırmak için 24 saatlik sorular hashlenerel Redis üzerinde tutulur.
JWT Yetkilendirme: Kullanıcı oturumları ve API erişimleri güvenli JWT tokenları ile yönetilir.

⚙️ Kurulum (Local & Cloud)
Ana dizinde bir .env dosyası oluşturun ve aşağıdaki şablonu doldurun:
# OpenAI API Settings
API_KEY=your_openai_api_key

# JWT & Core Security
SECRET_KEY=yüksek_güvenlikli_karmaşık_bir_string_girin
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Cloud Infrastructure (AWS & Upstash)
REDIS_URL=rediss://default:password@endpoint:6379
DATABASE_URL=postgresql+asyncpg://user:pass@rds_endpoint:5432/dbname

# Connection Settings
NEXT_PUBLIC_API_URL=http://ec2_ip_adresiniz/api/v1

Docker ile Başlatma:
docker-compose up --build -d

Geliştirici: Bartu Önder - 2. Sınıf Yazılım Mühendisliği Öğrencisi
Hedef: Backend/Software Engineering - AI Security
