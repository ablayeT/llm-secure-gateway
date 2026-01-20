import re
import base64
import binascii

class PromptFirewall:
    def __init__(self):
        # 1. Signatures d'attaques (Blacklist)
        self.attack_patterns = [
            r"ignore previous instructions",
            r"system override",
            r"pwned",
            r"drop table",
            r"rm -rf",
            r"cat /etc/passwd"
        ]

        # 2. Signatures de données sensibles (DLP - Data Leakage Prevention)
        self.sensitive_patterns = {
            # Détection d'email simple
            "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            # Détection (simplifiée) de Carte Bancaire (16 chiffres)
            "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
            # Détection de Clés API (Ex: AWS)
            "AWS_KEY": r"AKIA[0-9A-Z]{16}"
        }

    def _decode_base64(self, text: str) -> str:
        """Tente de décoder du Base64 caché pour voir ce qu'il y a derrière."""
        try:
            # Nettoyage du texte pour voir s'il ressemble à du B64
            # Note : mplémentation basique pour l'exemple
            if len(text) > 20 and "=" in text: 
                decoded_bytes = base64.b64decode(text, validate=True)
                return decoded_bytes.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            pass
        return text

    def scan(self, prompt: str) -> dict:
        """
        Analyse complète : Décodage -> Attaques -> Fuite de données
        """
        
        # ÉTAPE 1 : Anti-Obfuscation
        # Si le hacker essaie de cacher "rm -rf" en Base64, donc démasque le.
        decoded_prompt = self._decode_base64(prompt)
        
        # Si le décodage a révélé un texte différent, donc logue l'info
        check_target = decoded_prompt if decoded_prompt != prompt else prompt

        # ÉTAPE 2 : Détection d'Attaques (Injection)
        for pattern in self.attack_patterns:
            if re.search(pattern, check_target, re.IGNORECASE):
                return {
                    "is_safe": False,
                    "action": "BLOCK",
                    "reason": f"Attaque détectée (Signature: {pattern})"
                }

        # ÉTAPE 3 : Data Leakage Prevention (DLP)
        # Pas forcément bloqué, mais AVERTISSEMENT ou REDACT (Censure)
        anonymized_prompt = prompt
        alerts = []
        
        for label, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, prompt)
            if matches:
                alerts.append(label)
                # Censure : remplaceR "bob@gmail.com" par "<EMAIL_REDACTED>"
                anonymized_prompt = re.sub(pattern, f"<{label}_REDACTED>", anonymized_prompt)

        # RÉSULTAT FINAL
        return {
            "is_safe": True,
            "action": "ALLOW" if not alerts else "ANONYMIZE",
            "reason": f"Fuite de données prévenue: {', '.join(alerts)}" if alerts else "Clean",
            "sanitized_input": anonymized_prompt
        }