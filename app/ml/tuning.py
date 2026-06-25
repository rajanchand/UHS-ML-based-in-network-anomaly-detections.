import optuna
import numpy as np
from sklearn.model_selection import train_test_split
from app.ml.models import get_model

# Disable optuna logs to avoid cluttering stderr
optuna.logging.set_verbosity(optuna.logging.WARNING)

class HyperparameterTuner:
    """
    Optimizes hyperparameters for RandomForest, XGBoost, LSTM, and Autoencoder models
    using Optuna. Uses a validation split for rapid evaluation.
    """

    @staticmethod
    def tune(model_type, X_train, y_train, n_trials=5, random_state=42):
        """
        Run Optuna optimization study.

        Returns:
            Dict containing best_params and optimization logs.
        """
        # Split into training and validation sets for parameter evaluation
        X_t, X_val, y_t, y_val = train_test_split(
            X_train, y_train, test_size=0.2, random_state=random_state
        )

        def objective(trial):
            params = {}

            if model_type == 'random_forest':
                params['n_estimators'] = trial.suggest_int('n_estimators', 20, 100)
                params['max_depth'] = trial.suggest_int('max_depth', 5, 15)
                
                from sklearn.ensemble import RandomForestClassifier
                model = RandomForestClassifier(
                    n_estimators=params['n_estimators'],
                    max_depth=params['max_depth'],
                    random_state=random_state,
                    n_jobs=-1
                )
                model.fit(X_t, y_t)
                score = float(model.score(X_val, y_val))

            elif model_type == 'xgboost':
                params['n_estimators'] = trial.suggest_int('n_estimators', 20, 100)
                params['max_depth'] = trial.suggest_int('max_depth', 3, 8)
                params['learning_rate'] = trial.suggest_float('learning_rate', 0.01, 0.2)
                
                import xgboost as xgb
                model = xgb.XGBClassifier(
                    n_estimators=params['n_estimators'],
                    max_depth=params['max_depth'],
                    learning_rate=params['learning_rate'],
                    random_state=random_state,
                    n_jobs=-1,
                    eval_metric='logloss'
                )
                model.fit(X_t, y_t)
                score = float(model.score(X_val, y_val))

            elif model_type == 'lstm':
                params['hidden_dim'] = trial.suggest_int('hidden_dim', 16, 64)
                params['lr'] = trial.suggest_float('lr', 1e-4, 1e-2, log=True)
                params['epochs'] = 2  # Keep low for tuning latency
                
                from app.ml.models import LSTMModel
                model = LSTMModel(
                    hidden_dim=params['hidden_dim'],
                    lr=params['lr'],
                    epochs=params['epochs']
                )
                model.train(X_t, y_t)
                
                from sklearn.metrics import accuracy_score
                preds = model.predict(X_val)
                score = float(accuracy_score(y_val, preds))

            elif model_type == 'autoencoder':
                params['encoding_dim'] = trial.suggest_int('encoding_dim', 8, 32)
                params['lr'] = trial.suggest_float('lr', 1e-4, 1e-2, log=True)
                params['epochs'] = 2
                
                from app.ml.models import AutoencoderModel
                model = AutoencoderModel(
                    encoding_dim=params['encoding_dim'],
                    lr=params['lr'],
                    epochs=params['epochs']
                )
                # Unsupervised: train and val without labels
                model.train(X_t)
                
                # For autoencoder, objective is to minimize reconstruction loss on validation set
                import torch
                model.model.eval()
                with torch.no_grad():
                    val_tensor = torch.tensor(X_val, dtype=torch.float32)
                    reconstructed = model.model(val_tensor)
                    loss = torch.mean((val_tensor - reconstructed) ** 2).item()
                # Optuna minimizes this
                return loss

            else:
                raise ValueError(f"Tuning not supported for model type: {model_type}")

            # Return accuracy score to maximize
            return score

        direction = "minimize" if model_type == "autoencoder" else "maximize"
        study = optuna.create_study(direction=direction)
        study.optimize(objective, n_trials=n_trials)

        trial_logs = []
        for t in study.trials:
            trial_logs.append({
                'trial_number': t.number,
                'params': t.params,
                'value': t.value,
                'status': str(t.state)
            })

        return {
            'best_params': study.best_params,
            'best_value': study.best_value,
            'trials': trial_logs
        }
