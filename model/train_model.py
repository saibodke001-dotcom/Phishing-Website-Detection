import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pickle
import warnings

warnings.filterwarnings('ignore')

# Set paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODEL_DIR = os.path.join(BASE_DIR, 'model')

# Ensure directories exist
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATASET_DIR, 'phishing_dataset.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')

def generate_synthetic_data(num_samples=2000):
    """
    Generates a realistic synthetic dataset for phishing detection if a real one isn't available.
    NOTE FOR PROJECT DEMO/VIVA: Swap this data loading step with a real dataset like 
    the UCI Phishing dataset by simply reading the CSV using pandas.
    """
    print("Generating synthetic dataset...")
    np.random.seed(42)
    
    # 0 = Legitimate, 1 = Phishing
    labels = np.random.choice([0, 1], size=num_samples)
    
    data = []
    for label in labels:
        if label == 1:
            # Phishing URL characteristics
            having_ip_address = np.random.choice([0, 1], p=[0.7, 0.3])
            url_length = np.random.choice([0, 1], p=[0.4, 0.6])
            having_at_symbol = np.random.choice([0, 1], p=[0.8, 0.2])
            prefix_suffix_dash = np.random.choice([0, 1], p=[0.2, 0.8])
            multi_subdomains = np.random.choice([0, 1], p=[0.3, 0.7])
            https_token = np.random.choice([0, 1], p=[0.8, 0.2])
            has_https = np.random.choice([0, 1], p=[0.8, 0.2]) # Many phishing sites use https now
            shortining_service = np.random.choice([0, 1], p=[0.7, 0.3])
            count_dots = np.random.randint(1, 10)
            count_digits = np.random.randint(0, 50)
            count_special_chars = np.random.randint(0, 15)
            has_suspicious_words = np.random.choice([0, 1], p=[0.4, 0.6])
            domain_age = np.random.choice([0, 1], p=[0.1, 0.9]) # Often young
            favicon_mismatch = np.random.choice([0, 1], p=[0.6, 0.4])
            redirects = np.random.choice([0, 1], p=[0.5, 0.5])
        else:
            # Legitimate URL characteristics
            having_ip_address = np.random.choice([0, 1], p=[0.99, 0.01])
            url_length = np.random.choice([0, 1], p=[0.9, 0.1])
            having_at_symbol = np.random.choice([0, 1], p=[0.99, 0.01])
            prefix_suffix_dash = np.random.choice([0, 1], p=[0.9, 0.1])
            multi_subdomains = np.random.choice([0, 1], p=[0.9, 0.1])
            https_token = np.random.choice([0, 1], p=[0.99, 0.01])
            has_https = np.random.choice([0, 1], p=[0.1, 0.9])
            shortining_service = np.random.choice([0, 1], p=[0.9, 0.1])
            count_dots = np.random.randint(1, 4)
            count_digits = np.random.randint(0, 10)
            count_special_chars = np.random.randint(0, 5)
            has_suspicious_words = np.random.choice([0, 1], p=[0.95, 0.05])
            domain_age = np.random.choice([0, 1], p=[0.9, 0.1])
            favicon_mismatch = np.random.choice([0, 1], p=[0.95, 0.05])
            redirects = np.random.choice([0, 1], p=[0.9, 0.1])

        data.append([
            having_ip_address, url_length, having_at_symbol, prefix_suffix_dash,
            multi_subdomains, https_token, has_https, shortining_service,
            count_dots, count_digits, count_special_chars, has_suspicious_words,
            domain_age, favicon_mismatch, redirects, label
        ])

    columns = [
        'having_ip_address', 'url_length', 'having_at_symbol', 'prefix_suffix_dash',
        'multi_subdomains', 'https_token', 'has_https', 'shortining_service',
        'count_dots', 'count_digits', 'count_special_chars', 'has_suspicious_words',
        'domain_age', 'favicon_mismatch', 'redirects', 'Label'
    ]
    
    df = pd.DataFrame(data, columns=columns)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Synthetic dataset saved to {DATASET_PATH}")
    return df

def train_and_evaluate():
    # 1. Load Data
    if not os.path.exists(DATASET_PATH):
        df = generate_synthetic_data()
    else:
        df = pd.read_csv(DATASET_PATH)
        print(f"Loaded dataset from {DATASET_PATH}")
        
    X = df.drop('Label', axis=1)
    y = df['Label']

    # 2. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Initialize Models
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
    }

    # Try importing XGBoost
    try:
        from xgboost import XGBClassifier
        models['XGBoost'] = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    except ImportError:
        print("XGBoost not installed. Proceeding with other models.")

    results = {}
    best_model = None
    best_f1 = 0

    print("\n--- Model Training & Comparison ---")
    print(f"{'Model Name':<20} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 70)

    # 4. Train and Evaluate
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        results[name] = {'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1': f1, 'Model': model}
        
        print(f"{name:<20} | {acc:.4f}     | {prec:.4f}      | {rec:.4f}   | {f1:.4f}")

        # Select Best Model based on F1-Score
        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_model_name = name

    print("-" * 70)
    print(f"\nBest Model Selected: {best_model_name} (F1-Score: {best_f1:.4f})")

    # 5. Save the Best Model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(best_model, f)
    print(f"Model saved successfully to {MODEL_PATH}")

    # 6. Output Confusion Matrix of the Best Model
    y_pred_best = best_model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred_best)
    print("\nConfusion Matrix (Best Model):")
    print(f"True Negative (Legitimate): {cm[0][0]}")
    print(f"False Positive (Phishing missed): {cm[0][1]}")
    print(f"False Negative (False alarm): {cm[1][0]}")
    print(f"True Positive (Phishing caught): {cm[1][1]}")
    
    # 7. Print Feature Importance (if applicable)
    if hasattr(best_model, 'feature_importances_'):
        print("\nTop 5 Important Features:")
        importances = best_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        features = X.columns
        for i in range(5):
            print(f"{i+1}. {features[indices[i]]} ({importances[indices[i]]:.4f})")

if __name__ == "__main__":
    train_and_evaluate()
