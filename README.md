# Phishing Website Detection using Machine Learning

## Abstract / Objective
The objective of this final-year diploma project is to develop a reliable, machine-learning-powered web application capable of detecting phishing websites in real-time. By extracting lexical and host-based features from a given URL without relying on third-party security APIs, the system uses classification algorithms to predict whether a URL is legitimate or malicious. 

## Technology Stack
- **Backend**: Python, Flask
- **Machine Learning**: scikit-learn (Logistic Regression, Random Forest, Gradient Boosting)
- **Data Manipulation**: pandas, numpy
- **Frontend**: HTML5, CSS3, Bootstrap 5

## Project Structure
```text
phishing_detection/
├── dataset/
│   └── phishing_dataset.csv       # The synthetic/real dataset used for training
├── model/
│   ├── train_model.py             # Script to train, compare, and save the ML model
│   └── phishing_model.pkl         # The serialized best ML model
├── templates/
│   ├── index.html                 # Homepage with URL input form
│   └── result.html                # Prediction result and feature breakdown page
├── static/
│   └── style.css                  # Custom styling
├── app.py                         # Flask application
├── feature_extraction.py          # Custom URL feature extraction logic
├── model_training.ipynb           # Jupyter notebook for EDA and model visualization
├── requirements.txt               # Dependencies
└── README.md                      # Project documentation
```

## Setup and Installation

1. **Clone or Download the Repository**
2. **Navigate to the Project Directory**:
   ```bash
   cd phishing_detection
   ```
3. **Install Dependencies**:
   Ensure you have Python installed, then run:
   ```bash
   pip install -r requirements.txt
   ```
4. **Train the Model & Generate Dataset**:
   This project includes a synthetic data generator to run end-to-end immediately.
   ```bash
   python model/train_model.py
   ```
   *Note: For the final viva/presentation, you can swap the synthetic data loader in `train_model.py` with a real dataset like the UCI Phishing dataset.*
5. **Run the Flask Application**:
   ```bash
   python app.py
   ```
6. **Access the Web App**:
   Open your browser and navigate to `http://localhost:5000`

## Machine Learning Algorithm Used
The project trains multiple algorithms (Logistic Regression, Random Forest, Gradient Boosting, XGBoost) and selects the best-performing one based on the F1-Score. 
- **Random Forest** & **Gradient Boosting** are powerful ensemble methods that handle non-linear relationships well and resist overfitting.
- **Logistic Regression** is used as a fast, interpretable baseline.
The `train_model.py` script automatically compares these and saves the best model as `phishing_model.pkl`.

## Features Extracted
The `feature_extraction.py` script extracts 15+ features manually from any URL, including:
- URL length and depth
- IP address usage instead of domain names
- Presence of suspicious symbols (`@`, `-`)
- Subdomain count
- HTTPS token presence
- Suspicious keyword detection (e.g., 'login', 'secure', 'bank')
- URL shortening service usage
- Domain age (via WHOIS)

## Screenshots
*(Add screenshots of the web application here for the final report)*
- **Home Page**: [Placeholder for index.html screenshot]
- **Prediction Result**: [Placeholder for result.html screenshot]
- **EDA Visualizations**: [Placeholder for Jupyter Notebook graphs]

## Future Scope
- **Browser Extension**: Develop a Chrome/Firefox extension that uses this backend API to warn users automatically before they visit a phishing site.
- **Deep Learning**: Implement LSTM or CNN models that treat URLs as character sequences to detect complex obfuscation.
- **Real-time API Integration**: Integrate APIs like Google Safe Browsing or PhishTank for hybrid detection (Rule-based + ML + Blacklist).
