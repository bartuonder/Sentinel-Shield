🛡️ Sentinel-Shield: Cloud-Native AI Security Gateway
Sentinel-Shield, modern web uygulamaları ve LLM tabanlı sistemler için geliştirilmiş, API Key yönetimli bir güvenlik katmanıdır. İstekler hedef sisteme ulaşmadan önce Sentinel-Shield üzerinden geçer; saldırılar (OWASP Top 10 & LLM Vulnerabilities) bloklanır ve hassas veriler maskelenir.

☁️ Cloud & Altyapı Mimari
Proje, yüksek erişilebilirlik ve ölçeklenebilirlik için tamamen bulut teknolojileri üzerine inşa edilmiştir:

Hosting: AWS EC2 (Dockerized Deployment)

Veritabanı: AWS RDS (PostgreSQL) - Kalıcı log ve kullanıcı yönetimi

Cache & Rate Limit: Upstash Redis - Hızlı kural kontrolü ve oturum yönetimi

Orkestrasyon: Docker Compose (Frontend & Backend izolasyonu)

🌟 Öne Çıkan Özellikler
SaaS Model: Kullanıcılar kayıt olup kendi API anahtarlarını oluşturabilir ve projelerini saniyeler içinde korumaya başlayabilir.

Tehdit Engelleme: SQL Injection, XSS ve gelişmiş Prompt Injection saldırılarını gerçek zamanlı durdurur.

DLP (Veri Sızıntısı Önleme): PII Scanner modülü ile TCKN, IBAN ve email gibi verileri otomatik maskeler.

Akıllı Ban Sistemi: Belirlenen eşiği aşan saldırgan IP'leri otomatik olarak Blacklist'e alır.

🛠️ Teknoloji Yığını
Backend: FastAPI, SQLAlchemy, Pydantic

Frontend: Next.js

Yapay Zeka: OpenAI GPT-4o-mini (Semantik Güvenlik Analizi)

⚙️ Kurulum ve Yapılandırma
Projeyi çalıştırmak için ana dizinde bir .env dosyası oluşturun ve aşağıdaki şablonu kendi bilgilerinizle doldurun:

# OpenAI API Key (Semantic analysis)
API_KEY=your_openai_api_key_here

# Security & JWT Configuration
SECRET_KEY=your_long_random_secret_string_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Cloud Infrastructure Connections
REDIS_URL=rediss://default:your_password@your_upstash_endpoint:6379
DATABASE_URL=postgresql+asyncpg://user:password@your_rds_endpoint:5432/db_name

# Frontend Connection
NEXT_PUBLIC_API_URL=http://your_ec2_public_ip/api/v1

📦 Çalıştırma:
# Docker konteynerlerini inşa eder ve arka planda çalıştırır
docker-compose up --build -d

Geliştirici: Bartu - Yazılım Mühendisliği
Hedef: Security Software Engineering & AI Security
