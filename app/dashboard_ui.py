import streamlit as st
import requests
import pandas as pd
import plotly.express as px

API_BASE_URL = "http://127.0.0.1:8000/api/v1"

st.set_page_config(
    page_title="Sentinel Shield SaaS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

if 'auth_token' not in st.session_state:
    st.session_state.auth_token = None


def auth_screen():
    st.title("🛡️ Sentinel Shield")
    tab1, tab2 = st.tabs(["Giriş Yap", "Kayıt Ol"])
    with tab1:
        with st.form("login"):
            email = st.text_input("Email")
            password = st.text_input("Şifre", type="password")
            if st.form_submit_button("Giriş Yap"):
                try:
                    res = requests.post(f"{API_BASE_URL}/auth/login", data={"username": email, "password": password})
                    if res.status_code == 200:
                        st.session_state.auth_token = res.json().get("access_token")
                        st.rerun()
                    else:
                        st.error("Giriş başarısız.")
                except:
                    st.error("Sunucuya bağlanılamadı.")

    with tab2:
        with st.form("signup"):
            name = st.text_input("İsim")
            email = st.text_input("Email")
            password = st.text_input("Şifre", type="password")
            if st.form_submit_button("Kayıt Ol"):
                requests.post(f"{API_BASE_URL}/auth/signup",
                              json={"email": email, "password": password, "full_name": name})
                st.success("Kayıt olundu, giriş yapabilirsiniz.")


def main_dashboard():
    headers = {"Authorization": f"Bearer {st.session_state.auth_token}"}

    try:
        user = requests.get(f"{API_BASE_URL}/dashboard/me", headers=headers).json()
        stats = requests.get(f"{API_BASE_URL}/dashboard/stats", headers=headers).json()
    except:
        st.session_state.auth_token = None
        st.rerun()
        return

    with st.sidebar:
        st.title(user.get("full_name"))
        if st.button("Çıkış Yap"):
            st.session_state.auth_token = None
            st.rerun()

    st.title("Güvenlik Paneli")
    st.info(f"🔑 API Key: `{user.get('api_key')}`")

    c1, c2, c3, c4 = st.columns(4)
    total = stats.get("total_requests", 0)
    blocked = stats.get("blocked_attacks", 0)
    banned = stats.get("global_banned_ips", 0)

    c1.metric("Toplam Trafik", total)
    c2.metric("Engellenen Saldırı", blocked, delta_color="inverse")
    c3.metric("Banlanan IP", banned)

    score = 100
    if total > 0:
        ratio = blocked / total
        score = max(0, 100 - int(ratio * 100))
    c4.metric("Güvenlik Skoru", f"%{score}")

    st.markdown("---")

    tabs = st.tabs(["📊 Aktivite Logları", "🚫 Yasaklı IP'ler", "📈 Analiz Grafikleri"])

    with tabs[0]:
        try:
            logs = requests.get(f"{API_BASE_URL}/dashboard/logs", headers=headers).json()
            if logs:
                df = pd.DataFrame(logs)

                df['durum'] = df['is_allowed'].apply(lambda x: "✅ Temiz" if x else "🛡️ Engellendi")

                st.dataframe(
                    df[['timestamp', 'ip_address', 'scanner_name', 'durum', 'request_text']],
                    use_container_width=True
                )
            else:
                st.info("Henüz log yok.")
        except:
            st.error("Loglar yüklenemedi.")

    with tabs[1]:
        try:
            bans = requests.get(f"{API_BASE_URL}/dashboard/bans", headers=headers).json()
            if bans:
                st.dataframe(pd.DataFrame(bans)[['ip_address', 'reason', 'banned_at']], use_container_width=True)
            else:
                st.success("Banlı IP yok.")
        except:
            st.error("Liste yüklenemedi.")

    with tabs[2]:
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            st.subheader("Trafik Analizi")
            allowed_count = max(0, total - blocked)
            traffic_data = pd.DataFrame({
                "Tip": ["Temiz Trafik", "Saldırı"],
                "Miktar": [allowed_count, blocked]
            })
            if total > 0:
                fig1 = px.pie(traffic_data, values="Miktar", names="Tip",
                              color="Tip", color_discrete_map={"Temiz Trafik": "green", "Saldırı": "red"},
                              hole=0.4)
                st.plotly_chart(fig1, use_container_width=True)
            else:
                st.info("Veri yok.")

        with col_g2:
            st.subheader("Tehdit Dağılımı")
            dist = stats.get("attack_distribution", [])
            if dist:
                df_dist = pd.DataFrame(dist)
                fig2 = px.bar(df_dist, x="name", y="value",
                              labels={"name": "Saldırı Modülü", "value": "Sayı"},
                              color="value", title="Saldırı Tipleri")
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("Henüz saldırı tespit edilmedi.")


if st.session_state.auth_token:
    main_dashboard()
else:
    auth_screen()