import streamlit as st
import requests
import pandas as pd
import time
import re
from datetime import datetime, timedelta

# --- 1. CONFIGURATION ---
st.set_page_config(
    page_title="Secure Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. CSS ---
st.markdown("""
<style>
    .stDeployButton {display:none;}
    footer {visibility: hidden;}
    .dlp-alert {
        background-color: #fff7e6; 
        border-left: 5px solid #fa8c16;
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 12px;
        font-family: sans-serif;
        color: #7c2d12; 
    }
</style>
""", unsafe_allow_html=True)

API_URL = "http://localhost:8080/analyze"

# --- 3. SESSION STATE ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- 4. LOGIN ---
def login_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("# 🔒 Portail Sécurisé")
        with st.form("login_form"):
            username = st.text_input("Identifiant")
            password = st.text_input("Mot de passe", type="password")
            submitted = st.form_submit_button("Connexion", use_container_width=True)
            if submitted:
                if username == "admin" and password == "admin123":
                    st.session_state.authenticated = True
                    st.session_state.role = "admin"
                    st.rerun()
                elif username == "user" and password == "user123":
                    st.session_state.authenticated = True
                    st.session_state.role = "user"
                    st.rerun()
                else:
                    st.error("Identifiants incorrects.")

# --- 5. APP PRINCIPALE ---
def main_app():
    AVATARS = {"user": "👤", "assistant": "🛡️"}

    with st.sidebar:
        st.title("🎛️ Console")
        if st.session_state.role == "admin":
            page = st.radio("Navigation", ["💬 Chat Sécurisé", "📊 Audit SOC"])
        else:
            page = "💬 Chat Sécurisé"
            st.info("Mode : Employé (Restreint)")
        
        st.markdown("---")
        st.write(f"Connecté en : **{st.session_state.role.upper()}**")
        if st.button("Déconnexion"):
            st.session_state.authenticated = False
            st.rerun()

    # --- CHAT ---
    if page == "💬 Chat Sécurisé":
        st.subheader("💬 Assistant IA d'Entreprise")
        
        for msg in st.session_state.messages:
            with st.chat_message(msg["role"], avatar=AVATARS.get(msg["role"])):
                if msg.get("is_html"):
                    st.markdown(msg["content"], unsafe_allow_html=True)
                else:
                    st.markdown(msg["content"])

        if prompt := st.chat_input("Votre message..."):
            with st.chat_message("user", avatar=AVATARS["user"]):
                st.markdown(prompt)
            st.session_state.messages.append({"role": "user", "content": prompt, "is_html": False})

            try:
                response = requests.post(API_URL, json={"user_input": prompt})
                if response.status_code == 200:
                    data = response.json()
                    if data["original_censored"]:
                        alert = f"<div class='dlp-alert'><b>⚠️ DLP ACTIVÉ</b><br>Prompt nettoyé : <i>{data['sanitized_input']}</i></div>"
                        with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                            st.markdown(alert, unsafe_allow_html=True)
                            st.markdown(data["llm_reply"]["answer"])
                        st.session_state.messages.append({"role": "assistant", "content": alert, "is_html": True})
                        st.session_state.messages.append({"role": "assistant", "content": data["llm_reply"]["answer"], "is_html": False})
                    else:
                        with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                            st.markdown(data["llm_reply"]["answer"])
                        st.session_state.messages.append({"role": "assistant", "content": data["llm_reply"]["answer"], "is_html": False})
                elif response.status_code == 403:
                    err = "⛔ **ACTION BLOQUÉE** : Tentative d'injection détectée."
                    with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                        st.error(err)
                    st.session_state.messages.append({"role": "assistant", "content": err, "is_html": False})
            except Exception as e:
                st.error(f"Erreur connexion : {e}")

    # --- DASHBOARD (PARSER) ---
    elif page == "📊 Audit SOC":
        st.subheader("📊 Security Operations Center (SOC)")
        if st.button("🔄 Actualiser"): st.rerun()
        
        try:
            logs = []
            with open("security_audit.log", "r") as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line: continue

                    # 1. Recherche de la  date
                    match_date = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                    if not match_date: continue
                    
                    start_idx = match_date.start()
                    
                    # --- Retouche sur l'HEURE ---
                    raw_ts = line[start_idx : start_idx + 19]
                    try:
                        # convertir le texte en date, on ajoute 1h, on remet en texte
                        dt_obj = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S")
                        dt_obj = dt_obj + timedelta(hours=1)
                        timestamp_part = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        timestamp_part = raw_ts # Si ça rate, on garde l'originale
                    
                    rest_of_line = line[start_idx + 19 :]
                    
                    niveau = "INFO"
                    raw_message = rest_of_line

                    # 2. Détection du niveau
                    if "WARNING" in rest_of_line:
                        niveau = "WARNING"
                        parts = rest_of_line.split("WARNING", 1)
                        if len(parts) > 1: raw_message = parts[1]
                    elif "INFO" in rest_of_line:
                        niveau = "INFO"
                        parts = rest_of_line.split("INFO", 1)
                        if len(parts) > 1: raw_message = parts[1]
                    
                    # 3. Nettoyage
                    clean_msg = re.sub(r'^[\s\t\-"|,]+', '', raw_message).strip()
                    
                    logs.append({"Heure": timestamp_part, "Niveau": niveau, "Message": clean_msg})
            
            if logs:
                df = pd.DataFrame(logs)
                k1, k2, k3 = st.columns(3)
                k1.metric("Flux Total", len(df))
                k2.metric("Menaces Bloquées 🛡️", len(df[df['Message'].str.contains("ATTACK|BLOCKED|Injection", case=False)]), delta_color="inverse")
                k3.metric("Fuites Censurées 🧩", len(df[df['Message'].str.contains("REDACTED|SANITIZED", case=False)]), delta_color="normal")
                
                st.dataframe(df.iloc[::-1], use_container_width=True)
            else:
                st.info("Aucun log lisible trouvé.")

        except FileNotFoundError:
            st.warning("Fichier log introuvable.")

if not st.session_state.authenticated:
    login_page()
else:
    main_app()