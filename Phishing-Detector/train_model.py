import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import os

# Load dataset
df = pd.read_csv('test_dataset.csv')

# Features and labels
X = df[['sender_spoofed', 'has_urgency', 'has_links', 'link_suspicious', 'body_length']]
y = df['label'].apply(lambda x: 1 if x == 'phishing' else 0)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Accuracy metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print("=" * 50)
print("MODEL TRAINING RESULTS")
print("=" * 50)
print(f"Accuracy:  {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall:    {recall:.2%}")
print(f"F1-Score:  {f1:.2%}")
print(f"Confusion Matrix:\n{cm}")
print("=" * 50)
print("Model saved as 'phishing_model.pkl'")

# Save model
joblib.dump(model, 'phishing_model.pkl')