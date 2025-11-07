import pandas as pd
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings('ignore')

def train_and_save_model():
    # Load your dataset
    data, meta = arff.loadarff('Training Dataset.arff')
    df = pd.DataFrame(data)
    
    # Decode byte strings
    df = df.map(lambda x: x.decode() if isinstance(x, bytes) else x)
    
    # Print column names to see the exact spelling
    print("Dataset columns:", df.columns.tolist())
    
    # Convert to numeric
    feature_columns = [col for col in df.columns if col != 'Result']
    for col in feature_columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df['Result'] = pd.to_numeric(df['Result'], errors='coerce')
    
    # Fill NaN values
    df.fillna(-1, inplace=True)
    
    # Prepare features and target
    X = df[feature_columns]
    y = df['Result']
    
    # Print feature names for verification
    print("Feature names in training data:", X.columns.tolist())
    
    # Train model
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Save model
    joblib.dump(model, 'phishing_model.pkl')
    print("Model trained and saved as 'phishing_model.pkl'")
    
    # Test accuracy
    accuracy = model.score(X_test, y_test)
    print(f"Model accuracy: {accuracy:.2f}")

if __name__ == "__main__":
    train_and_save_model()