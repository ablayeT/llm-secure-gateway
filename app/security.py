import re
import base64
import binascii

# --- 1. CONFIGURATION DES MENACES (GLOBAL) ---

# Liste noire des attaques (Injections de prompt)
# --- MOTIFS D'ATTAQUES (Renforcés grâce au Pentest) ---
INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore constraints",     # <--- Patch pour la faille critique
    r"system override",
    r"pwned",
    r"drop table",
    r"select \* from",
    r"rm -rf",
    r"cat /etc/passwd",
    r"/bin/bash",
    r"do anything now",
    r"dan mode",
    r"<script>",
    r"execute.*python",        # <--- Patch pour l'exécution de code
    r"import os"               # <--- Patch pour l'import système
]

# Modèles de données sensibles (DLP)
PII_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "AWS_KEY": r"AKIA[0-9A-Z]{16}",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b"
}

# --- 2. FONCTIONS UTILITAIRES ---

def _decode_base64(text: str) -> str:
    """
    Fonction intelligente qui tente de démasquer du texte caché en Base64.
    Exemple : "cm0gLXJmIC8=" devient "rm -rf /"
    """
    try:
        # Un peu de nettoyage pour éviter les faux positifs
        clean_text = text.strip()
        # Un texte Base64 valide a souvent une longueur multiple de 4 ou finit par =
        if len(clean_text) > 4 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', clean_text):
            decoded_bytes = base64.b64decode(clean_text, validate=True)
            decoded_str = decoded_bytes.decode('utf-8')
            # Vérifier si le résultat est lisible (pas du binaire pur)
            if decoded_str.isprintable():
                return decoded_str
    except (binascii.Error, UnicodeDecodeError, ValueError):
        pass
    return text

# --- 3. FONCTIONS PRINCIPALES (Appelées par main.py) ---

def analyze_injection(text: str) -> tuple[bool, str]:
    """
    Vérifie si le texte contient une attaque.
    Retourne : (is_attack: bool, details: str)
    """
    if not text:
        return False, "Empty input"

    # ÉTAPE A : Anti-Obfuscation ( décodage du Base64 caché)
    decoded_text = _decode_base64(text)
    
    # Scanne du texte original et du texte décodé
    targets_to_scan = [text]
    if decoded_text != text:
        targets_to_scan.append(decoded_text)

    # ÉTAPE B : Scan des signatures
    for target in targets_to_scan:
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                # Si on trouve un motif interdit
                return True, f"Injection detected: '{pattern}'"

    return False, "Clean"

def clean_pii(text: str) -> tuple[str, list]:
    """
    Anonymise les données sensibles.
    Retourne : (texte_nettoyé: str, logs: list)
    """
    sanitized_text = text
    logs = []

    for label, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, sanitized_text)
        if matches:
            count = len(matches)
            logs.append(f"Found {count} {label}")
            # Remplacement par <EMAIL_REDACTED>, <CREDIT_CARD_REDACTED>...
            sanitized_text = re.sub(pattern, f"<{label}_REDACTED>", sanitized_text)
    
    return sanitized_text, logs