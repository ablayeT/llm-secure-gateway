import re

class PromptFirewall:
    def __init__(self):
        # Liste de signatures d'attaques classiques (Regex)
        # Exemple de liste d'une base de données mise à jour.
        self.blacklist_patterns = [
            r"ignore previous instructions",   # Le classique
            r"system override",              # Tentative de prise de contrôle
            r"ignore all rules",             # Contournement
            r"pwned",                        # Signature hacker
            r"drop table",                   # Injection SQL (au cas où)
            r"sudo ",                        # Commande système
            r"rm -rf"                        # Destruction de fichiers
        ]

    def scan(self, prompt: str) -> dict:
        """
        Analyse le prompt pour détecter des menaces.
        Retourne un dictionnaire avec le statut et la raison.
        """
        for pattern in self.blacklist_patterns:
            # Recherche insensible à la casse (IGNORECASE)
            if re.search(pattern, prompt, re.IGNORECASE):
                return {
                    "is_safe": False,
                    "reason": f"Signature malveillante détectée : '{pattern}'"
                }
        
        # Si aucune signature n'est trouvée
        return {
            "is_safe": True,
            "reason": "Aucune menace détectée"
        }