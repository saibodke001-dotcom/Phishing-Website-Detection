from flask import Flask, render_template, request
import pickle
import numpy as np
import urllib.parse
from feature_extraction import extract_features
import os

app = Flask(__name__)

# Load the trained model
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'phishing_model.pkl')

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    model = None
    print("Warning: Model not found. Please run 'python model/train_model.py' first.")

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return render_template('index.html', error="Model not trained yet. Please contact the administrator.")
    
    url = request.form.get('url', '').strip()
    
    if not url:
        return render_template('index.html', error="Please enter a valid URL.")

    # Extract features
    try:
        features_dict = extract_features(url)
        # Convert dictionary values to a 2D numpy array for prediction
        # The order must match the training dataset columns
        feature_order = [
            'having_ip_address', 'url_length', 'having_at_symbol', 'prefix_suffix_dash',
            'multi_subdomains', 'https_token', 'has_https', 'shortining_service',
            'count_dots', 'count_digits', 'count_special_chars', 'has_suspicious_words',
            'domain_age', 'favicon_mismatch', 'redirects'
        ]
        
        feature_vector = np.array([[features_dict[feat] for feat in feature_order]])
        
        # Predict
        prediction = model.predict(feature_vector)[0]
        
        # Confidence score (if supported by model)
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(feature_vector)[0]
            confidence = round(max(probabilities) * 100, 2)
        else:
            confidence = "N/A"
            
        result = "Phishing" if prediction == 1 else "Legitimate"
        
        # Determine some key factors to show the user
        key_factors = []
        if features_dict['having_ip_address']: key_factors.append("Uses an IP address instead of domain")
        if features_dict['url_length']: key_factors.append("URL length is unusually long")
        if features_dict['having_at_symbol']: key_factors.append("Contains '@' symbol")
        if features_dict['prefix_suffix_dash']: key_factors.append("Domain contains '-' symbol")
        if features_dict['has_suspicious_words']: key_factors.append("Contains suspicious keywords")
        if features_dict['shortining_service']: key_factors.append("Uses URL shortening service")
        if features_dict['domain_age']: key_factors.append("Domain age is relatively young or unknown")
        
        if not key_factors and result == "Legitimate":
            key_factors.append("No obvious suspicious lexical features detected")
        elif not key_factors and result == "Phishing":
            key_factors.append("Pattern matches known phishing characteristics based on ML model")

        return render_template('result.html', 
                               url=url, 
                               result=result, 
                               confidence=confidence, 
                               key_factors=key_factors)
                               
    except Exception as e:
        return render_template('index.html', error=f"An error occurred while processing the URL: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
