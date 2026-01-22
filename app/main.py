from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.security import analyze_injection, clean_pii
from openai import OpenAI # La librairie officielle
import logging
import time
import os
from dotenv import load_dotenv

# Chargement des variables d'environnement 
load_dotenv()

# --- 1. CONFIGURATION OPENROUTER ---
# Récupèration de la clé depuis le fichier depuis les  variables d'environnement 
API_KEY = os.getenv("OPENROUTER_API_KEY")

# Configuration du client (OpenRouter utilise le même format qu'OpenAI)
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=API_KEY,
)

# Modèle choisi (possibilité de choisir "openai/gpt-4o-mini" ou "anthropic/claude-3-haiku")
# "meta-llama/llama-3-8b-instruct" est très performant et très peu cher. 
TARGET_MODEL = "meta-llama/llama-3-8b-instruct"

# --- CONFIGURATION AUDIT ---
logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = FastAPI(
    title="Secure LLM Gateway (OpenRouter Edition)",
    description="Passerelle de production connectée à OpenRouter.",
    version="3.0.0"
)

class PromptRequest(BaseModel):
    user_input: str

# --- 2. FONCTION D'APPEL RÉEL (Le vrai Proxy) ---
def query_openrouter(safe_prompt: str):
    """
    Envoie le prompt nettoyé à OpenRouter et récupère la vraie réponse.
    """
    if not API_KEY:
        return {"error": "API Key manquante dans le fichier .env"}

    try:
        completion = client.chat.completions.create(
            extra_headers={
                "HTTP-Referer": "https://mon-projet-etudiant.com", # Requis par OpenRouter
                "X-Title": "LLM Secure Gateway",
            },
            model=TARGET_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "Tu es un assistant utile et professionnel. Tu réponds de manière concise."
                },
                {
                    "role": "user",
                    "content": safe_prompt
                }
            ],
        )
        # On extrait le texte de la réponse
        return {
            "source": "OpenRouter",
            "model": TARGET_MODEL,
            "answer": completion.choices[0].message.content
        }
    except Exception as e:
        logging.error(f"OpenRouter Error: {str(e)}")
        return {"error": "Le LLM est injoignable", "details": str(e)}

@app.get("/")
def health_check():
    return {"status": "online", "provider": "OpenRouter"}

@app.post("/analyze")
def analyze_prompt(request: PromptRequest):
    """
    Workflow complet : Sécurité -> Nettoyage -> Appel API Réel.
    """
    input_text = request.user_input
    start_time = time.time()

    # 1. Bloquer les attaques
    is_attack, attack_details = analyze_injection(input_text)
    if is_attack:
        logging.warning(f"⛔ ATTACK BLOCKED | {attack_details}")
        raise HTTPException(status_code=403, detail=f"Attaque détectée: {attack_details}")

    # 2. Nettoyer les données sensibles
    sanitized_text, logs = clean_pii(input_text)

    # 3. Log de sécurité

 # 3. Log de sécurité (AVEC PREUVE DU PAYLOAD)
    action = "forwarded" if sanitized_text == input_text else "sanitized_and_forwarded"
    # log de ce qui part vraiment vers l'API
    logging.info(f"Traffic Processed | Action: {action} | OUTGOING PAYLOAD: '{sanitized_text}'")

    # 4. APPEL RÉEL VERS OPENROUTER
    # Renvoit du texte PROPRE
    llm_response = query_openrouter(sanitized_text)

    return {
        "status": "success",
        "original_censored": sanitized_text != input_text,
        "sanitized_input": sanitized_text,
        "llm_reply": llm_response,
        "processing_time": round(time.time() - start_time, 2)
    }