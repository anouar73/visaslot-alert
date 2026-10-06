# VisaSlot Alert — version complète

## Inclus
- site public responsive ;
- inscription / connexion ;
- mot de passe haché PBKDF2 ;
- session utilisateur ;
- tableau de bord ;
- création, pause et suppression d'alertes ;
- historique des détections ;
- journal d'envoi des notifications ;
- email SMTP ;
- WhatsApp Cloud API ;
- endpoint sécurisé `/api/detections` ;
- extension Chrome/Edge ;
- Docker + volume persistant SQLite.

## Important
Le système ne contourne pas les CAPTCHA ou protections anti-bot et ne réserve pas automatiquement de rendez-vous. L'extension observe seulement une page que l'utilisateur a déjà ouverte.

## Test local avec Docker
1. Copier `.env.example` vers `.env`.
2. Modifier `SECRET_KEY` et `MONITOR_SECRET`.
3. Lancer :

```bash
docker compose up --build
```

4. Ouvrir `http://localhost:8000`.

## Test sans Docker
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.app:app --reload
```

## Email Gmail SMTP
Pour un compte Gmail, utilisez un **mot de passe d'application**, pas le mot de passe Gmail normal. Configurez `SMTP_USERNAME`, `SMTP_PASSWORD` et `SMTP_FROM`.

## WhatsApp Cloud API
Créer un template approuvé nommé par défaut `visa_slot_alert` avec trois variables :
1. centre ;
2. démarche ;
3. détail du créneau.

Puis remplir `WHATSAPP_TOKEN` et `WHATSAPP_PHONE_NUMBER_ID`.

## Extension
Dans Chrome/Edge :
- Extensions → Mode développeur → Charger l'extension non empaquetée ;
- sélectionner le dossier `extension` ;
- ouvrir les options ;
- mettre l'URL publique du backend et `MONITOR_SECRET` ;
- configurer le centre, la démarche et, idéalement, un sélecteur CSS précis.

## Déploiement sur n'importe quel hébergeur Docker
Le conteneur écoute sur le port 8000. Il faut :
- créer un service Docker depuis ce dossier ;
- monter un disque persistant sur `/data` ;
- copier les variables `.env` dans les variables d'environnement du service ;
- mettre `HTTPS_ONLY=1` après activation HTTPS ;
- définir `BASE_URL` avec le domaine public.

## Production
Avant une commercialisation réelle, ajouter idéalement : récupération de mot de passe, vérification email, CGU, politique de confidentialité, consentement WhatsApp, sauvegardes automatiques, limitation de débit et base PostgreSQL si le trafic devient important.
