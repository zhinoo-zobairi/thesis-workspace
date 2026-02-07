#!/usr/bin/env python3
"""
MQTT Anomaly Detection Model Training

Trains an Autoencoder for MQTT attack detection.
- Train on normal traffic only
- High reconstruction error = anomaly
- Export to TF Lite for C++ integration

Author: Zhinoo Zobairi
Date: February 2026

Usage:
    python train_mqtt_model.py --data mqtt_features.csv --output mqtt_model.tflite
"""

import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_curve, auc, classification_report, confusion_matrix
)
import matplotlib.pyplot as plt

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model

# Feature count must match mqtt_ml.cc
MQTT_ML_NUM_FEATURES = 28


# =============================================================================
# Model Architecture
# =============================================================================

def create_autoencoder(input_dim: int, encoding_dim: int = 8) -> Model:
    """
    Create an Autoencoder model.
    
    Architecture:
        Input (28) -> Dense(16) -> Dense(8) -> Dense(16) -> Dense(28)
        
    The model learns to compress and reconstruct normal patterns.
    High reconstruction error = anomaly.
    """
    # Encoder
    inputs = keras.Input(shape=(input_dim,))
    x = layers.Dense(16, activation='relu')(inputs)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.2)(x)
    encoded = layers.Dense(encoding_dim, activation='relu', name='encoding')(x)
    
    # Decoder
    x = layers.Dense(16, activation='relu')(encoded)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.2)(x)
    decoded = layers.Dense(input_dim, activation='sigmoid')(x)  # sigmoid for [0,1] output
    
    # Full autoencoder
    autoencoder = Model(inputs, decoded, name='mqtt_autoencoder')
    
    return autoencoder


# =============================================================================
# Data Preparation
# =============================================================================

def load_data(csv_path: Path) -> tuple:
    """Load and prepare data from CSV."""
    print(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    
    # Features are all columns except 'label'
    feature_cols = [col for col in df.columns if col != 'label']
    X = df[feature_cols].values.astype(np.float32)
    y = df['label'].values.astype(np.int32)
    
    print(f"  Total samples: {len(X)}")
    print(f"  Normal samples: {np.sum(y == 0)}")
    print(f"  Attack samples: {np.sum(y == 1)}")
    print(f"  Features: {X.shape[1]}")
    
    return X, y, feature_cols


# =============================================================================
# Training
# =============================================================================

def train_autoencoder(X_train: np.ndarray, X_val: np.ndarray,
                      epochs: int = 50, batch_size: int = 32) -> tuple:
    """
    Train autoencoder on NORMAL data only.
    
    The idea: train on normal patterns, then use reconstruction error
    to detect anomalies.
    """
    # Create model
    model = create_autoencoder(X_train.shape[1])
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='mse'
    )
    model.summary()
    
    # Callbacks
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss',
            factor=0.5,
            patience=5,
            min_lr=1e-6
        )
    ]
    
    # Train
    history = model.fit(
        X_train, X_train,  # Autoencoder: reconstruct input
        epochs=epochs,
        batch_size=batch_size,
        validation_data=(X_val, X_val),
        callbacks=callbacks,
        verbose=1
    )
    
    return model, history


# =============================================================================
# Evaluation
# =============================================================================

def calculate_reconstruction_threshold(model: Model, X_normal: np.ndarray,
                                       percentile: float = 95) -> float:
    """
    Calculate anomaly threshold based on reconstruction error on normal data.
    """
    reconstructions = model.predict(X_normal, verbose=0)
    mse = np.mean(np.square(X_normal - reconstructions), axis=1)
    threshold = np.percentile(mse, percentile)
    print(f"Reconstruction error threshold (p{percentile}): {threshold:.6f}")
    return threshold


def evaluate_autoencoder(model: Model, X_test: np.ndarray, y_test: np.ndarray,
                        threshold: float) -> None:
    """Evaluate autoencoder using reconstruction error."""
    reconstructions = model.predict(X_test, verbose=0)
    mse = np.mean(np.square(X_test - reconstructions), axis=1)
    
    # Predict: high error = anomaly (attack)
    y_pred = (mse > threshold).astype(int)
    
    print("\n" + "="*60)
    print("Autoencoder Evaluation (Reconstruction Error)")
    print("="*60)
    print(f"\nThreshold: {threshold:.6f}")
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # ROC curve
    fpr, tpr, _ = roc_curve(y_test, mse)
    roc_auc = auc(fpr, tpr)
    print(f"\nROC AUC: {roc_auc:.4f}")
    
    return fpr, tpr, roc_auc


def plot_roc_curve(fpr: np.ndarray, tpr: np.ndarray, 
                   roc_auc: float, output_path: Path) -> None:
    """Plot and save ROC curve."""
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, 
             label=f'ROC curve (AUC = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('MQTT Anomaly Detection - ROC Curve')
    plt.legend(loc='lower right')
    plt.grid(True, alpha=0.3)
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"ROC curve saved to {output_path}")


def plot_training_history(history, output_path: Path) -> None:
    """Plot training history."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    
    # Loss
    axes[0].plot(history.history['loss'], label='Train')
    axes[0].plot(history.history['val_loss'], label='Validation')
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Loss')
    axes[0].set_title('Training Loss')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)
    
    # Metrics (if available)
    if 'accuracy' in history.history:
        axes[1].plot(history.history['accuracy'], label='Train Acc')
        axes[1].plot(history.history['val_accuracy'], label='Val Acc')
        axes[1].set_ylabel('Accuracy')
    elif 'auc' in history.history:
        axes[1].plot(history.history['auc'], label='Train AUC')
        axes[1].plot(history.history['val_auc'], label='Val AUC')
        axes[1].set_ylabel('AUC')
    axes[1].set_xlabel('Epoch')
    axes[1].set_title('Training Metrics')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"Training history saved to {output_path}")


# =============================================================================
# TF Lite Export
# =============================================================================

def export_to_tflite(model: Model, output_path: Path, 
                     threshold: float = 0.5) -> None:
    """
    Export model to TensorFlow Lite format for C++ integration.
    """
    print(f"\nExporting model to TF Lite: {output_path}")
    
    # Convert to TFLite
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    
    # Optimize for size and speed
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    
    # Convert
    tflite_model = converter.convert()
    
    # Save
    with open(output_path, 'wb') as f:
        f.write(tflite_model)
    
    print(f"  Model size: {len(tflite_model) / 1024:.2f} KB")
    
    # Also save threshold to a separate file
    threshold_path = output_path.with_suffix('.threshold')
    with open(threshold_path, 'w') as f:
        f.write(f"{threshold}")
    print(f"  Threshold saved to: {threshold_path}")
    
    # Verify the model
    interpreter = tf.lite.Interpreter(model_content=tflite_model)
    interpreter.allocate_tensors()
    
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    print(f"  Input shape: {input_details[0]['shape']}")
    print(f"  Output shape: {output_details[0]['shape']}")
    print(f"  Input dtype: {input_details[0]['dtype']}")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Train MQTT anomaly detection model"
    )
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Path to features CSV file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="mqtt_model.tflite",
        help="Output TF Lite model path"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=50,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=32,
        help="Training batch size"
    )
    parser.add_argument(
        "--test_split",
        type=float,
        default=0.2,
        help="Test set split ratio"
    )
    
    args = parser.parse_args()
    
    # Load data
    X, y, feature_names = load_data(Path(args.data))
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_split, stratify=y, random_state=42
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )
    
    print(f"\nData split:")
    print(f"  Training:   {len(X_train)} samples")
    print(f"  Validation: {len(X_val)} samples")
    print(f"  Test:       {len(X_test)} samples")
    
    output_path = Path(args.output)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Train on NORMAL data only
    X_train_normal = X_train[y_train == 0]
    X_val_normal = X_val[y_val == 0]
    
    print(f"\nTraining autoencoder on {len(X_train_normal)} normal samples")
    
    model, history = train_autoencoder(
        X_train_normal, X_val_normal,
        epochs=args.epochs,
        batch_size=args.batch_size
    )
    
    # Calculate threshold from validation set
    threshold = calculate_reconstruction_threshold(model, X_val_normal)
    
    # Evaluate
    fpr, tpr, roc_auc = evaluate_autoencoder(model, X_test, y_test, threshold)
    
    # Plot results
    plot_roc_curve(fpr, tpr, roc_auc, output_dir / "roc_curve.png")
    plot_training_history(history, output_dir / "training_history.png")
    
    # Export to TF Lite
    export_to_tflite(model, output_path, threshold)
    
    print("\n" + "="*60)
    print("Training Complete!")
    print("="*60)
    print(f"Model saved to: {output_path}")
    print(f"Threshold: {threshold:.6f}")
    
    return 0


if __name__ == "__main__":
    exit(main())
