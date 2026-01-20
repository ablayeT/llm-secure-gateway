from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.security import PromptFirewall # Import du module

# Initialisation de l'application
app = FastAPI(
    title="LLM Secure Gateway",
    description="Pare-feu pour filtrer les injections de prompt",
    version="1.0.0"
)

# Initialisation du moteur de sécurité
firewall = PromptFirewall()

class PromptRequest(BaseModel):
    user_input: str
    metadata: dict | None = None

@app.get("/")
def health_check():
    return {"status": "running", "service": "LLM Firewall"}

@app.post("/analyze")
def analyze_prompt(request: PromptRequest):
    """
    Analyse le prompt entrant via le Firewall.
    Bloque la requête si une injection est détectée.
    """
    # 1. Scan du prompt
    analysis = firewall.scan(request.user_input)

    # 2. Prise de décision
    if not analysis["is_safe"]:
        # LOG DE SÉCURITÉ (Très important pour un Admin Sys !)
        print(f"🚨 ALERT: Attaque bloquée ! Input: '{request.user_input}' - Raison: {analysis['reason']}")
        
        # Renvoit d'une erreur 403 (Forbidden)
        raise HTTPException(status_code=403, detail=analysis["reason"])

    # 3. Si c'est safe donc validation
    return {
        "status": "allowed",
        "message": "Prompt validé et sécurisé.",
        "original_input": request.user_input
    }