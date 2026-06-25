"""
ML Models
=========
Implementations of three anomaly detection models with consistent interfaces.

Models:
    RandomForestModel   — Ensemble classifier (supervised)
    XGBoostModel        — Gradient boosting classifier (supervised)
    IsolationForestModel — Unsupervised anomaly detection

Each model implements train(), predict(), evaluate(), and get_model() methods
for a consistent API across the pipeline.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
)

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except Exception:
    HAS_XGBOOST = False


class BaseModel:
    """
    Base class for all ML models.
    Provides a consistent interface for training, prediction, and evaluation.
    """

    def __init__(self):
        self.model = None
        self.is_trained = False

    def train(self, X_train, y_train):
        """Train the model on training data."""
        raise NotImplementedError

    def predict(self, X):
        """Generate predictions."""
        raise NotImplementedError

    def predict_proba(self, X):
        """Generate prediction probabilities (if available)."""
        raise NotImplementedError

    def evaluate(self, X_test, y_test):
        """
        Evaluate model performance on test data.

        Returns:
            Dict with accuracy, precision, recall, f1_score, roc_auc.
        """
        y_pred = self.predict(X_test)

        # Convert to binary for standard detection metrics (anomaly vs normal)
        y_test_bin = (np.asarray(y_test) > 0).astype(int)
        y_pred_bin = (np.asarray(y_pred) > 0).astype(int)

        metrics = {
            'accuracy': float(accuracy_score(y_test_bin, y_pred_bin)),
            'precision': float(precision_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'recall': float(recall_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'f1_score': float(f1_score(y_test_bin, y_pred_bin, average='binary', zero_division=0)),
            'roc_auc': 0.0,
        }

        # ROC AUC requires probability scores
        try:
            y_proba = self.predict_proba(X_test)
            if y_proba is not None and len(np.unique(y_test_bin)) == 2:
                # If multiclass probability prediction, reduce to single anomaly probability
                if len(y_proba.shape) > 1 and y_proba.shape[1] > 1:
                    anomaly_proba = y_proba[:, 1:].sum(axis=1)
                else:
                    anomaly_proba = y_proba
                metrics['roc_auc'] = float(roc_auc_score(y_test_bin, anomaly_proba))
        except Exception:
            pass

        return metrics

    def get_model(self):
        """Return the underlying sklearn/xgboost model for SHAP."""
        return self.model


class RandomForestModel(BaseModel):
    """
    Random Forest Classifier for network anomaly detection.

    Strengths:
        - Robust to overfitting
        - Handles mixed feature types well
        - Built-in feature importance
        - Parallelisable training
    """

    def __init__(self, n_estimators=100, max_depth=None, random_state=42):
        super().__init__()
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,              # Use all CPU cores
            class_weight='balanced', # Handle class imbalance
            min_samples_split=5,
            min_samples_leaf=2,
        )

    def train(self, X_train, y_train):
        """Train the Random Forest classifier."""
        self.model.fit(X_train, y_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """Generate binary predictions (0=normal, 1=anomaly)."""
        return self.model.predict(X)

    def predict_proba(self, X):
        """Get full probability matrix for all classes."""
        classes = getattr(self.model, 'classes_', [])
        if len(classes) == 1:
            if classes[0] == 0:
                return np.zeros(len(X))
            else:
                return np.ones(len(X))
        return self.model.predict_proba(X)


class XGBoostModel(BaseModel):
    """
    XGBoost Gradient Boosting Classifier for network anomaly detection.

    Strengths:
        - Superior accuracy on tabular data
        - Built-in regularisation (L1/L2)
        - Handles missing values natively
        - Feature importance via gain metrics
    """

    def __init__(self, n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42):
        super().__init__()
        if not HAS_XGBOOST:
            raise ImportError('XGBoost is not installed. Install with: pip install xgboost')

        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state,
            n_jobs=-1,
            eval_metric='logloss',
            use_label_encoder=False,
            scale_pos_weight=1,     # Adjusted dynamically in train()
            reg_alpha=0.1,          # L1 regularisation
            reg_lambda=1.0,         # L2 regularisation
        )

    def train(self, X_train, y_train):
        """Train the XGBoost classifier with early stopping awareness."""
        # Compute class weight ratio for imbalanced datasets
        n_positive = np.sum(y_train == 1)
        n_negative = np.sum(y_train == 0)
        if n_positive > 0 and len(np.unique(y_train)) == 2:
            self.model.set_params(scale_pos_weight=n_negative / n_positive)

        self.model.fit(X_train, y_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """Generate binary predictions."""
        return self.model.predict(X)

    def predict_proba(self, X):
        """Get full probability matrix for all classes."""
        classes = getattr(self.model, 'classes_', [])
        if len(classes) == 1:
            if classes[0] == 0:
                return np.zeros(len(X))
            else:
                return np.ones(len(X))
        return self.model.predict_proba(X)


class IsolationForestModel(BaseModel):
    """
    Isolation Forest for unsupervised anomaly detection.

    Strengths:
        - No labelled data required
        - Efficient on high-dimensional data
        - Linear time complexity
        - Detects novel/unknown anomalies

    Note: This model does not use the target column. It detects anomalies
    purely based on feature isolation properties.
    """

    def __init__(self, n_estimators=100, contamination=0.1, random_state=42):
        super().__init__()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,  # Expected anomaly proportion
            random_state=random_state,
            n_jobs=-1,
            max_samples='auto',
        )

    def train(self, X_train, y_train=None):
        """
        Train the Isolation Forest (unsupervised — ignores y_train).
        """
        self.model.fit(X_train)
        self.is_trained = True
        return self

    def predict(self, X):
        """
        Generate binary predictions.
        Isolation Forest returns 1 for normal, -1 for anomaly.
        We convert to 0=normal, 1=anomaly for consistency.
        """
        raw_predictions = self.model.predict(X)
        # Convert: -1 (anomaly) → 1, 1 (normal) → 0
        return np.where(raw_predictions == -1, 1, 0)

    def predict_proba(self, X):
        """
        Get anomaly scores.
        Uses the decision function (negative = more anomalous).
        Normalised to [0, 1] range.
        """
        scores = self.model.decision_function(X)
        # Normalise: more negative = higher anomaly probability
        min_score = scores.min()
        max_score = scores.max()
        if max_score - min_score == 0:
            return np.zeros(len(X))
        normalised = 1 - (scores - min_score) / (max_score - min_score)
        return normalised


# --- PyTorch Deep Learning Models ---

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class PyTorchLSTMNet(nn.Module):
        def __init__(self, input_dim, hidden_dim=64, num_layers=2, output_dim=2):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
            self.fc = nn.Linear(hidden_dim, output_dim)
            
        def forward(self, x):
            out, _ = self.lstm(x)
            out = out[:, -1, :]  # Take output of the last step
            return self.fc(out)


    class PyTorchAutoencoderNet(nn.Module):
        def __init__(self, input_dim, encoding_dim=16):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, encoding_dim * 2),
                nn.ReLU(),
                nn.Linear(encoding_dim * 2, encoding_dim),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(encoding_dim, encoding_dim * 2),
                nn.ReLU(),
                nn.Linear(encoding_dim * 2, input_dim)
            )
            
        def forward(self, x):
            return self.decoder(self.encoder(x))


class LSTMModel(BaseModel):
    """
    PyTorch LSTM Classifier for temporal sequence analysis on network flow data.
    """

    def __init__(self, hidden_dim=64, num_layers=2, epochs=5, batch_size=32, lr=0.001, lookback=5):
        super().__init__()
        if not HAS_TORCH:
            raise ImportError("PyTorch is required for LSTMModel. Run 'pip install torch'")
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.lookback = lookback
        self.model = None

    def _create_sequences(self, X, y=None):
        X_seq = []
        for i in range(len(X)):
            if i < self.lookback - 1:
                # Pad sequence with the first sample for initial indices
                pad_len = self.lookback - 1 - i
                seq = [X[0]] * pad_len + list(X[0:i+1])
            else:
                seq = list(X[i - self.lookback + 1:i + 1])
            X_seq.append(seq)
        X_seq = np.array(X_seq, dtype=np.float32)
        
        if y is not None:
            y_seq = np.array(y, dtype=np.int64)
            return X_seq, y_seq
        return X_seq

    def train(self, X_train, y_train):
        X_seq, y_seq = self._create_sequences(X_train, y_train)
        input_dim = X_train.shape[1]
        
        # Binary or Multiclass classification output
        num_classes = len(np.unique(y_train))
        output_dim = max(2, num_classes)
        
        self.model = PyTorchLSTMNet(input_dim, self.hidden_dim, self.num_layers, output_dim)
        self.model.train()
        
        dataset = TensorDataset(torch.tensor(X_seq), torch.tensor(y_seq))
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        optimizer = optim.Adam(self.model.parameters(), lr=self.lr)
        criterion = nn.CrossEntropyLoss()
        
        for epoch in range(self.epochs):
            for batch_x, batch_y in loader:
                optimizer.zero_grad()
                outputs = self.model(batch_x)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                
        self.is_trained = True
        return self

    def predict(self, X):
        self.model.eval()
        X_seq = self._create_sequences(X)
        with torch.no_grad():
            outputs = self.model(torch.tensor(X_seq))
            predictions = torch.argmax(outputs, dim=1).numpy()
        return predictions

    def predict_proba(self, X):
        self.model.eval()
        X_seq = self._create_sequences(X)
        with torch.no_grad():
            outputs = self.model(torch.tensor(X_seq))
            probabilities = nn.functional.softmax(outputs, dim=1).numpy()
        return probabilities


class AutoencoderModel(BaseModel):
    """
    PyTorch Autoencoder for unsupervised reconstruction-based anomaly detection.
    """

    def __init__(self, encoding_dim=16, epochs=5, batch_size=32, lr=0.001, contamination=0.1):
        super().__init__()
        if not HAS_TORCH:
            raise ImportError("PyTorch is required for AutoencoderModel. Run 'pip install torch'")
        self.encoding_dim = encoding_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.contamination = contamination
        self.threshold = 0.0
        self.model = None

    def train(self, X_train, y_train=None):
        input_dim = X_train.shape[1]
        self.model = PyTorchAutoencoderNet(input_dim, self.encoding_dim)
        self.model.train()
        
        dataset = TensorDataset(torch.tensor(X_train, dtype=torch.float32), torch.tensor(X_train, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        
        optimizer = optim.Adam(self.model.parameters(), lr=self.lr)
        criterion = nn.MSELoss()
        
        for epoch in range(self.epochs):
            for batch_x, _ in loader:
                optimizer.zero_grad()
                reconstructed = self.model(batch_x)
                loss = criterion(reconstructed, batch_x)
                loss.backward()
                optimizer.step()
                
        # Determine anomaly detection threshold based on contamination level
        self.model.eval()
        with torch.no_grad():
            train_reconstructed = self.model(torch.tensor(X_train, dtype=torch.float32)).numpy()
            train_errors = np.mean((X_train - train_reconstructed) ** 2, axis=1)
            self.threshold = float(np.percentile(train_errors, 100 * (1 - self.contamination)))
            
        self.is_trained = True
        return self

    def predict(self, X):
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(torch.tensor(X, dtype=torch.float32)).numpy()
            errors = np.mean((X - reconstructed) ** 2, axis=1)
        return np.where(errors > self.threshold, 1, 0)

    def predict_proba(self, X):
        self.model.eval()
        with torch.no_grad():
            reconstructed = self.model(torch.tensor(X, dtype=torch.float32)).numpy()
            errors = np.mean((X - reconstructed) ** 2, axis=1)
        # Min-max scale errors to [0, 1] range to simulate anomaly probability score
        min_err = errors.min()
        max_err = errors.max()
        if max_err - min_err == 0:
            return np.zeros(len(X))
        normalised = (errors - min_err) / (max_err - min_err)
        return normalised


# --- Factory ---

def get_model(model_type):
    """
    Factory function to create a model instance by type string.

    Args:
        model_type: One of 'random_forest', 'xgboost', 'isolation_forest', 'lstm', 'autoencoder'.

    Returns:
        Model instance.

    Raises:
        ValueError: If model_type is not recognised.
    """
    models = {
        'random_forest': RandomForestModel,
        'xgboost': XGBoostModel,
        'isolation_forest': IsolationForestModel,
        'lstm': LSTMModel,
        'autoencoder': AutoencoderModel,
    }

    if model_type not in models:
        raise ValueError(f'Unknown model type: {model_type}. Choose from: {list(models.keys())}')

    return models[model_type]()
