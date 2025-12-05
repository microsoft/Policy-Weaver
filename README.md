# Projet Python BigQuery

Ce projet fournit une interface Python simple et efficace pour interroger Google BigQuery sur Google Cloud Platform.

## 🚀 Fonctionnalités

- Client BigQuery avec gestion d'erreurs robuste
- Configuration centralisée via variables d'environnement
- Exemples de requêtes courantes
- Support des paramètres de requête pour la sécurité
- Conversion automatique vers pandas DataFrame
- Upload de données depuis DataFrame

## 📋 Prérequis

- Python 3.8+
- Compte Google Cloud Platform avec BigQuery activé
- Fichier de clés de service GCP (optionnel si ADC configuré)

## 🔧 Installation

1. **Cloner le projet et installer les dépendances :**

```bash
pip install -r requirements.txt
```

2. **Configurer les variables d'environnement :**

Copiez le fichier `.env.example` vers `.env` et remplissez vos informations :

```bash
cp .env.example .env
```

Éditez le fichier `.env` :

```
GOOGLE_APPLICATION_CREDENTIALS=path/to/your/service-account-key.json
PROJECT_ID=your-gcp-project-id
DATASET_ID=your-dataset-id
BQ_LOCATION=US
BQ_JOB_TIMEOUT=300
```

## 🔑 Authentification

### Option 1: Fichier de clés de service
1. Créez un compte de service dans Google Cloud Console
2. Téléchargez le fichier JSON des clés
3. Définissez `GOOGLE_APPLICATION_CREDENTIALS` avec le chemin vers ce fichier

### Option 2: Application Default Credentials (ADC)
1. Installez Google Cloud CLI
2. Exécutez `gcloud auth application-default login`
3. Laissez `GOOGLE_APPLICATION_CREDENTIALS` vide

## 📁 Structure du projet

```
├── src/
│   ├── config.py              # Configuration de l'application
│   ├── bigquery_client.py     # Client principal BigQuery
│   └── queries.py             # Exemples de requêtes SQL
├── examples/
│   └── basic_usage.py         # Exemple d'utilisation
├── requirements.txt           # Dépendances Python
├── .env.example              # Modèle de configuration
├── .gitignore                # Fichiers à ignorer par Git
└── README.md                 # Cette documentation
```

## 🎯 Utilisation

### Exemple de base

```python
from src.bigquery_client import BigQueryClient
from src.config import Config

# Initialiser le client
client = BigQueryClient()

# Exécuter une requête
df = client.execute_query("""
    SELECT name, COUNT(*) as count
    FROM `my-project.my-dataset.my-table`
    GROUP BY name
    ORDER BY count DESC
    LIMIT 10
""")

print(df)
```

### Requête avec paramètres

```python
from google.cloud import bigquery

# Requête sécurisée avec paramètres
query = """
    SELECT *
    FROM `my-project.my-dataset.my-table`
    WHERE date_column >= @start_date
    AND category = @category
"""

parameters = [
    bigquery.ScalarQueryParameter("start_date", "DATE", "2024-01-01"),
    bigquery.ScalarQueryParameter("category", "STRING", "electronics")
]

df = client.execute_query(query, parameters)
```

### Lister les tables

```python
# Lister toutes les tables du dataset
tables = client.list_tables()
print("Tables disponibles:", tables)

# Obtenir des informations sur une table
table_info = client.get_table_info("my-table")
print(f"Nombre de lignes: {table_info['num_rows']}")
```

### Upload de données

```python
import pandas as pd

# Créer un DataFrame
df = pd.DataFrame({
    'name': ['Alice', 'Bob', 'Charlie'],
    'age': [25, 30, 35],
    'city': ['Paris', 'Lyon', 'Marseille']
})

# Uploader vers BigQuery
client.upload_dataframe(df, "my-new-table")
```

## 🏃‍♂️ Exécuter les exemples

```bash
python examples/basic_usage.py
```

## ⚡ Bonnes pratiques

1. **Sécurité** : Utilisez toujours des paramètres pour les requêtes avec des valeurs dynamiques
2. **Coûts** : Limitez vos requêtes avec `LIMIT` et filtres appropriés
3. **Performance** : Utilisez la localisation de dataset appropriée
4. **Monitoring** : Surveillez vos logs pour détecter les erreurs

## 🔧 Configuration avancée

### Timeout des requêtes
Modifiez `BQ_JOB_TIMEOUT` dans votre fichier `.env` pour ajuster le timeout (en secondes).

### Localisation des données
Définissez `BQ_LOCATION` selon la région de vos datasets (US, EU, etc.).

## 🐛 Dépannage

### Erreur d'authentification
- Vérifiez que votre fichier de clés de service est correct
- Ou configurez ADC avec `gcloud auth application-default login`

### Erreur de permissions
- Assurez-vous que votre compte de service a les permissions BigQuery appropriées
- Rôles recommandés : `BigQuery User`, `BigQuery Data Viewer`, `BigQuery Data Editor`

### Erreur de projet/dataset
- Vérifiez que `PROJECT_ID` et `DATASET_ID` sont corrects dans votre `.env`
- Assurez-vous que le dataset existe dans votre projet

## 📚 Documentation

- [Documentation BigQuery](https://cloud.google.com/bigquery/docs)
- [Client Python BigQuery](https://googleapis.dev/python/bigquery/latest/)
- [Documentation pandas](https://pandas.pydata.org/docs/)

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou une pull request.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.