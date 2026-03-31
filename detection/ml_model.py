import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


def train_and_evaluate(dataset_path="data/dataset.csv"):
    data = pd.read_csv(dataset_path)

    if data["label"].nunique() < 2:
        print(
            "ERROR: Dataset must contain at least two classes "
            "(benign and backdoor)."
        )
        return None

    X = data[
        ["process_count", "network_connections", "persistence_detected"]
    ]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )

    model = LogisticRegression()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))

    return model
