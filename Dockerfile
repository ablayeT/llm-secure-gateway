# Image Python officielle et légère (Slim)
FROM python:3.13-slim

# Répertoire de travail dans le conteneur
WORKDIR /app

# Optimisation du cache Docker : Copier d'abord les requirements
COPY requirements.txt .

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copierreste du code source
COPY . .

# Exposition du port 8000
EXPOSE 8000

# Commande de démarrage
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]