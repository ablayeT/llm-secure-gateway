import streamlit as st
import requests
import pandas as pd
import time

# --- 1. CONFIGURATION (Première ligne obligatoire) ---
st.set_page_config(
    page_title="Secure Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. CSS : DESIGN PRO & ACCESSIBLE ---
st.markdown("""
<style>
    /* Cacher les éléments parasites de Streamlit */
    .stDeployButton {display:none;}
    footer {visibility: hidden;}
    
    /* Style "DLP Alert" - Norme WCAG (Accessibilité)
       Fond: Ambre très clair (pas agressif)
       Bordure: Orange Solaire (Visible)
       Texte: Marron foncé (Contraste élevé pour la lecture)
    */
    .dlp-alert {
        background-color: #fff7e6; 
        border-left: 5px solid #fa8c16;
        padding: 12px;
        border-radius: 4px;
        margin-bottom: 12px;
        font-family: sans-serif;
        color: #7c2d12; 
    }
    
    .dlp-title {
        font-weight: bold;
        display: flex;
        align-items: center;
        gap: 8px;
    }
</style>
""", unsafe_allow_html=True)

# URL API
API_URL = "http://localhost:8000/analyze"

# --- 3. SESSION STATE ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "role" not in st.session_state:
    st.session_state.role = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# --- 4. PAGE DE LOGIN ---
def login_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("# 🔒 Portail Sécurisé")
        st.markdown("Authentification requise pour accéder à la Gateway LLM.")
        
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
        
        with st.expander("ℹ️ Comptes de démonstration"):
            st.code("admin / admin123\nuser / user123")

# --- 5. APPLICATION PRINCIPALE ---
def main_app():
    
    # --- DÉFINITION DES ICÔNES (AVATARS) ---
    # User: Silhouette neutre (Standard Pro)
    # Assistant: Bouclier (Rappelle la fonction de sécurité)
    AVATARS = {
        "user": "👤",
        "assistant": "🛡️"
    }

    # --- A. SIDEBAR ---
    with st.sidebar:
        st.title("🎛️ Console")
        
        if st.session_state.role == "admin":
            page = st.radio("Navigation", ["💬 Chat Sécurisé", "📊 Audit SOC"])
        else:
            page = "💬 Chat Sécurisé"
            st.info("Mode : Employé (Restreint)")
        
        st.markdown("---")
        # Affichage du rôle avec icône
        role_icon = "🔑" if st.session_state.role == "admin" else "💼"
        st.write(f"{role_icon} Connecté en : **{st.session_state.role.upper()}**")
        
        if st.button("Déconnexion", type="secondary"):
            st.session_state.authenticated = False
            st.session_state.messages = []
            st.rerun()

    # --- B. PAGE CHAT ---
    if page == "💬 Chat Sécurisé":
        st.subheader("💬 Assistant IA d'Entreprise")
        st.caption("Flux protégé par Secure Gateway v3.0")

        # 1. Historique des messages
        for msg in st.session_state.messages:
            role = msg["role"]
            with st.chat_message(role, avatar=AVATARS.get(role)):
                if msg.get("is_html"):
                    st.markdown(msg["content"], unsafe_allow_html=True)
                else:
                    st.markdown(msg["content"])

        # 2. Input (En bas)
        if prompt := st.chat_input("Posez votre question de manière sécurisée..."):
            
            # Affichage User
            with st.chat_message("user", avatar=AVATARS["user"]):
                st.markdown(prompt)
            st.session_state.messages.append({"role": "user", "content": prompt, "is_html": False})

            # Appel API
            try:
                response = requests.post(API_URL, json={"user_input": prompt})
                
                if response.status_code == 200:
                    data = response.json()
                    sanitized = data["sanitized_input"]
                    llm_reply = data["llm_reply"]["answer"]
                    
                    # CENSURE (DLP)
                    if data["original_censored"]:
                        # HTML Pro & Accessible (Ambre/Orange)
                        alert_html = f"""
                        <div class="dlp-alert">
                            <div class="dlp-title">⚠️ FILTRE DLP ACTIVÉ</div>
                            Données sensibles détectées et masquées.<br>
                            <small><b>Prompt nettoyé envoyé au LLM :</b> <i>{sanitized}</i></small>
                        </div>
                        """
                        with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                            st.markdown(alert_html, unsafe_allow_html=True)
                            st.markdown(llm_reply)
                        
                        st.session_state.messages.append({"role": "assistant", "content": alert_html, "is_html": True})
                        st.session_state.messages.append({"role": "assistant", "content": llm_reply, "is_html": False})
                    
                    # PAS DE CENSURE
                    else:
                        with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                            st.markdown(llm_reply)
                        st.session_state.messages.append({"role": "assistant", "content": llm_reply, "is_html": False})

                # BLOCAGE (INJECTION)
                elif response.status_code == 403:
                    error_msg = "⛔ **ACTION BLOQUÉE** : Tentative de manipulation du modèle détectée (Prompt Injection)."
                    with st.chat_message("assistant", avatar=AVATARS["assistant"]):
                        st.error(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg, "is_html": False})

            except Exception as e:
                st.error(f"Erreur technique passerelle : {e}")

    # --- C. PAGE DASHBOARD ---
    elif page == "📊 Audit SOC":
        st.subheader("📊 Security Operations Center (SOC)")
        
        col_btn, col_txt = st.columns([1, 5])
        with col_btn:
            if st.button("🔄 Actualiser"):
                st.rerun()
        
        try:
            logs = []
            with open("security_audit.log", "r") as f:
                for line in f.readlines():
                    parts = line.split(" - ")
                    if len(parts) >= 3:
                        logs.append({"Heure": parts[0], "Niveau": parts[1], "Message": parts[2].strip()})
            
            if logs:
                df = pd.DataFrame(logs)
                
                # KPIs avec Icônes claires
                k1, k2, k3 = st.columns(3)
                
                # Total
                k1.metric("Flux Total", len(df))
                
                # Attaques (Rouge/Inverse)
                attacks = len(df[df['Message'].str.contains("ATTACK BLOCKED")])
                k2.metric("Menaces Bloquées 🛡️", attacks, delta_color="inverse")
                
                # Fuites (Normal/Neutre)
                pii = len(df[df['Message'].str.contains("PII REDACTED")])
                k3.metric("Fuites Censurées 🧩", pii, delta_color="normal")
                
                st.divider()
                st.markdown("### 📜 Journal d'Audit")
                st.dataframe(df.iloc[::-1], use_container_width=True)
            else:
                st.info("Aucune donnée d'audit disponible.")
                
        except FileNotFoundError:
            st.warning("Logs introuvables. Vérifiez le volume Docker.")

# --- LANCEMENT ---
if not st.session_state.authenticated:
    login_page()
else:
    main_app()