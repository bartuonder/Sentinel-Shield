import streamlit as st
import requests
import pandas as pd
import plotly.express as px

API_BASE_URL = "http://127.0.0.1:8000/api/v1"

st.set_page_config(
    page_title="Sentinel Shield Panel",
    layout="wide",
    initial_sidebar_state="expanded"
)

if 'auth_token' not in st.session_state:
    st.session_state.auth_token = None


def login_screen():
    st.header("Giriş Yap")

    with st.form("login_form"):
        email = st.text_input("Email Adresi")
        password = st.text_input("Şifre", type="password")
        submit = st.form_submit_button("Giriş")

        if submit:
            if not email or not password:
                st.warning("Lütfen tüm alanları doldurun.")
                return

            try:
                payload = {"username": email, "password": password}
                response = requests.post(f"{API_BASE_URL}/auth/login", data=payload)

                if response.status_code == 200:
                    token_data = response.json()
                    st.session_state.auth_token = token_data.get("access_token")
                    st.rerun()
                else:
                    st.error("Giriş başarısız. Bilgilerinizi kontrol edin.")
            except requests.exceptions.ConnectionError:
                st.error("Sunucuya bağlanılamadı. Backend servisinin açık olduğundan emin olun.")


def main_dashboard():
    headers = {"Authorization": f"Bearer {st.session_state.auth_token}"}

    try:
        user_response = requests.get(f"{API_BASE_URL}/dashboard/me", headers=headers)
        if user_response.status_code != 200:
            st.session_state.auth_token = None
            st.rerun()
            return

        user_data = user_response.json()

        stats_response = requests.get(f"{API_BASE_URL}/dashboard/stats", headers=headers)
        dashboard_stats = stats_response.json() if stats_response.status_code == 200 else {}

    except Exception as e:
        st.error(f"Veri çekme hatası: {str(e)}")
        return

    with st.sidebar:
        st.subheader("Profil Bilgileri")
        st.write(f"**Kullanıcı:** {user_data.get('full_name')}")
        st.write(f"**Email:** {user_data.get('email')}")

        st.markdown("---")
        if st.button("Çıkış Yap"):
            st.session_state.auth_token = None
            st.rerun()

    st.title("Güvenlik Paneli")
    st.markdown("---")

    st.subheader("Entegrasyon Anahtarı")
    col_key, col_info = st.columns([3, 1])
    with col_key:
        st.code(user_data.get("api_key", "Mevcut Değil"), language="text")
    with col_info:
        st.info("Bu anahtarı header'da 'Authorization: Bearer <KEY>' formatında kullanın.")

    st.markdown("---")

    if dashboard_stats:
        total = dashboard_stats.get("total_requests", 0)
        blocked = dashboard_stats.get("blocked_attacks", 0)
        banned_ips = dashboard_stats.get("global_banned_ips", 0)

        security_score = 100
        if total > 0:
            ratio = blocked / total
            security_score = max(0, 100 - int(ratio * 100))

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Toplam İstek", total)
        m2.metric("Engellenen Tehdit", blocked)
        m3.metric("Sistem Güvenlik Skoru", f"%{security_score}")
        m4.metric("Kalıcı Banlanan IP", banned_ips)

        st.markdown("### Analiz ve Loglar")

        col_table, col_chart = st.columns([2, 1])

        with col_table:
            st.write("**Son Aktivite Kayıtları**")
            try:
                logs_response = requests.get(f"{API_BASE_URL}/dashboard/logs?limit=20", headers=headers)
                if logs_response.status_code == 200:
                    logs_data = logs_response.json()
                    if logs_data:
                        df = pd.DataFrame(logs_data)
                        display_df = df[['timestamp', 'scanner_name', 'status', 'request_text']]
                        st.dataframe(
                            display_df,
                            column_config={
                                "timestamp": "Zaman",
                                "scanner_name": "Tespit Modülü",
                                "status": "Durum",
                                "request_text": "İstek İçeriği"
                            },
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.info("Görüntülenecek kayıt bulunamadı.")
            except:
                st.error("Log verileri alınamadı.")

        with col_chart:
            st.write("**Engelleme Dağılımı**")
            dist_data = dashboard_stats.get("attack_distribution", [])
            if dist_data:
                df_dist = pd.DataFrame(dist_data)
                fig = px.pie(
                    df_dist,
                    values='value',
                    names='name',
                    color_discrete_sequence=px.colors.sequential.RdBu
                )
                fig.update_layout(margin=dict(t=0, b=0, l=0, r=0))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.caption("Grafik oluşturmak için yeterli veri yok.")

if st.session_state.auth_token:
    main_dashboard()
else:
    login_screen()