#!/usr/bin/env python3
"""
Train model on CIC-VPN2016 CSV and save best model to file for later DPI usage.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import xgboost as xgb
import joblib


def load_data(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    df["is_vpn"] = df["traffic_type"].str.startswith("VPN").astype(int)
    X_cols = df.select_dtypes(include=np.number).columns.drop(["traffic_type", "is_vpn"], errors="ignore")
    return df[X_cols].values, df["is_vpn"].values


def train_eval_random_forest(X_train, X_test, y_train, y_test, scaler):
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    y_pred_proba = rf.predict_proba(X_test)[:, 1]
    print("RandomForest classification report:")
    print(classification_report(y_test, y_pred, target_names=["NonVPN", "VPN"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
    return rf, roc_auc_score(y_test, y_pred_proba)


def train_eval_xgboost(X_train, X_test, y_train, y_test, scaler):
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    y_pred = xgb_model.predict(X_test)
    y_pred_proba = xgb_model.predict_proba(X_test)[:, 1]
    print("XGBoost classification report:")
    print(classification_report(y_test, y_pred, target_names=["NonVPN", "VPN"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
    return xgb_model, roc_auc_score(y_test, y_pred_proba)


def save_best_model(model, scaler, auc, model_path="vpn_model.joblib"):
    joblib.dump(
        {"model": model, "scaler": scaler, "auc": auc},
        model_path,
    )
    print(f"Model saved to {model_path}")


def main():
    csv_path = "consolidated_traffic_data.csv"
    model_path = "vpn_model.joblib"

    X, y = load_data(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print("Training RandomForest...")
    rf, rf_auc = train_eval_random_forest(X_train, X_test, y_train, y_test, scaler)

    print("\nTraining XGBoost...")
    xgb_model, xgb_auc = train_eval_xgboost(X_train, X_test, y_train, y_test, scaler)

    print(f"\nXGBoost AUC: {xgb_auc:.4f}, RandomForest AUC: {rf_auc:.4f}")

    # Save the best model (XGBoost)
    best_model = xgb_model
    best_auc = xgb_auc

    save_best_model(best_model, scaler, best_auc, model_path)


if __name__ == "__main__":
    main()