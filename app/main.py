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
    Analyse intelligente avec DLP et Anti-Obfuscation.
    """
    # 1. Scan complet
    analysis = firewall.scan(request.user_input)

    # 2. Si c'est une attaque -> 403
    if analysis["action"] == "BLOCK":
        print(f"🚨 ALERT: Attaque bloquée ! IP: Client - Raison: {analysis['reason']}")
        raise HTTPException(status_code=403, detail=analysis["reason"])

    # 3. Si c'est une fuite de données -> 200 mais avec le texte censuré
    if analysis["action"] == "ANONYMIZE":
        print(f"⚠️ WARNING: Données sensibles censurées. Type: {analysis['reason']}")
        return {
            "status": "modified",
            "message": "Prompt validé mais nettoyé pour confidentialité.",
            "original_input": "CENSURÉ", # Pas de renvoit de l'original par sécurité
            "sanitized_input": analysis["sanitized_input"] # Le texte propre à envoyer au LLM
        }

    # 4. Tout est propre
    return {
        "status": "allowed",
        "message": "Prompt validé.",
        "sanitized_input": request.user_input
    }