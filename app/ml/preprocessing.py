"""
Data Preprocessing
==================
Feature engineering and data preparation for network traffic analysis.

Handles:
    - Missing value imputation
    - Categorical encoding (Label + One-Hot)
    - Numerical feature scaling (StandardScaler)
    - Feature selection and validation
    - Train/test splitting
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False



class DataPreprocessor:
    """
    Preprocesses network traffic CSV data for ML model consumption.
    Handles mixed data types, missing values, and feature engineering.
    """

    # Class-level attack mapping
    ATTACK_MAP = {
        'normal': 0,
        'benign': 0,
        'ddos': 1,
        'dos': 2,
        'port scan': 3,
        'portscan': 3,
        'brute force': 4,
        'bruteforce': 4,
        'bot': 5,
        'bot attack': 5,
        'botnet': 5
    }

    def __init__(self, target_column='label'):
        """
        Args:
            target_column: Name of the target/label column in the dataset.
        """
        self.target_column = target_column
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []
        self.is_fitted = False

    def load_and_validate(self, file_path):
        """
        Load a CSV file and validate its structure.

        Args:
            file_path: Path to the CSV file.

        Returns:
            pandas DataFrame.

        Raises:
            ValueError: If the dataset is empty or invalid.
        """
        df = pd.read_csv(file_path)

        if df.empty:
            raise ValueError('Dataset is empty')

        if len(df) < 10:
            raise ValueError('Dataset must contain at least 10 records')

        # Strip leading/trailing whitespace from column names (CICIDS2017 uses ' Label')
        df.columns = df.columns.str.strip()

        return df

    def _resolve_target_column(self, df):
        """
        Resolve the target column name using fuzzy case-insensitive matching.
        CICIDS2017 uses ' Label' (with leading space); after stripping it becomes 'Label'.
        This method handles case mismatches between the user-provided target_column
        and the actual column name in the dataset.

        Returns:
            The actual column name found in df, or None if not found.
        """
        # Exact match first
        if self.target_column in df.columns:
            return self.target_column

        # Case-insensitive match
        target_lower = self.target_column.lower().strip()
        for col in df.columns:
            if col.lower().strip() == target_lower:
                return col

        # Partial match (e.g., 'label' in 'Label')
        for col in df.columns:
            if target_lower in col.lower().strip():
                return col

        return None

    def preprocess(self, df, fit=True):
        """
        Full preprocessing pipeline.

        Steps:
            1. Drop columns with >50% missing values
            2. Impute remaining missing values
            3. Encode categorical features
            4. Scale numerical features
            5. Split features and target

        Args:
            df: Input DataFrame.
            fit: Whether to fit transformers (True for training, False for inference).

        Returns:
            Tuple of (X: np.ndarray, y: np.ndarray, feature_names: list).
        """
        df = df.copy()

        # Replace inf and -inf with NaN to allow imputation
        df = df.replace([np.inf, -np.inf], np.nan)

        # Step 1: Drop columns with excessive missing values (>50%)
        threshold = len(df) * 0.5
        df = df.dropna(thresh=int(threshold), axis=1)

        # Step 2: Separate target if present
        y = None
        resolved_target = self._resolve_target_column(df)
        has_target = resolved_target is not None

        if has_target:
            y = df[resolved_target].copy()
            df = df.drop(columns=[resolved_target])

            # Encode target if categorical or string
            if y.dtype == object or y.dtype == str:
                y_mapped = []
                for val in y:
                    val_str = str(val).lower().strip()
                    mapped_val = 0
                    found = False
                    for key, num in DataPreprocessor.ATTACK_MAP.items():
                        if key in val_str:
                            mapped_val = num
                            found = True
                            break
                    if not found:
                        if 'normal' in val_str or 'benign' in val_str:
                            mapped_val = 0
                        else:
                            mapped_val = 1  # Default to DDoS/anomaly if general threat
                    y_mapped.append(mapped_val)
                y = np.array(y_mapped, dtype=int)
            else:
                y = y.fillna(0).astype(int).values
        else:
            # For unsupervised models, create dummy target
            y = np.zeros(len(df))

        # Align features to what was fitted if doing inference
        if not fit and self.is_fitted:
            aligned_df = pd.DataFrame(0.0, index=df.index, columns=self.feature_names)
            for col in self.feature_names:
                if col in df.columns:
                    aligned_df[col] = df[col]
                else:
                    col_lower = col.lower().strip()
                    matched = False
                    for df_col in df.columns:
                        if df_col.lower().strip() == col_lower:
                            aligned_df[col] = df[df_col]
                            matched = True
                            break
                    if not matched:
                        aligned_df[col] = 0.0
            df = aligned_df

        # Step 3: Handle missing values
        # Numerical: fill with median
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        for col in numeric_cols:
            df[col] = df[col].fillna(df[col].median())

        # Categorical: fill with mode, then encode
        categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
        for col in categorical_cols:
            df[col] = df[col].fillna(df[col].mode().iloc[0] if not df[col].mode().empty else 'unknown')

            if fit:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le
            else:
                if col in self.label_encoders:
                    # Handle unseen categories gracefully
                    le = self.label_encoders[col]
                    df[col] = df[col].astype(str).apply(
                        lambda x: le.transform([x])[0] if x in le.classes_
                        else len(le.classes_)
                    )
                else:
                    df[col] = 0

        # Step 4: Scale numerical features
        self.feature_names = df.columns.tolist()

        if not self.feature_names:
            raise ValueError(
                'The dataset contains no valid feature columns. '
                'All columns were dropped due to having more than 50% missing values (NaNs).'
            )

        if fit:
            X = self.scaler.fit_transform(df.values)
            self.is_fitted = True
        else:
            X = self.scaler.transform(df.values)

        return X, y, self.feature_names

    def balance_data(self, X_train, y_train, random_state=42):
        """
        Balances the training set using SMOTE if class imbalance is high.
        """
        if not HAS_SMOTE:
            return X_train, y_train
            
        unique, counts = np.unique(y_train, return_counts=True)
        if len(unique) < 2:
            return X_train, y_train
            
        min_count = counts.min()
        max_count = counts.max()
        
        # Apply SMOTE if minority class is less than 30% of majority class
        # and we have at least 6 samples to satisfy k_neighbors default or scaled
        if min_count > 6 and (min_count / max_count) < 0.3:
            try:
                k_neighbors = min(5, min_count - 1)
                smote = SMOTE(random_state=random_state, k_neighbors=k_neighbors)
                X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
                return X_resampled, y_resampled
            except Exception:
                pass
        return X_train, y_train

    def prepare_train_test(self, file_path, test_size=0.2, random_state=42, balance=True):
        """
        Load, preprocess, and split data into train/test sets.

        Args:
            file_path: Path to the CSV file.
            test_size: Fraction for the test set (default 20%).
            random_state: Random seed for reproducibility.
            balance: Whether to apply SMOTE balancing to X_train/y_train.

        Returns:
            Dict with X_train, X_test, y_train, y_test, feature_names.
        """
        df = self.load_and_validate(file_path)
        X, y, feature_names = self.preprocess(df, fit=True)

        # Check if dataset has both classes for classification
        # Use fuzzy matching to detect the target column (handles CICIDS2017 ' Label')
        check_df = pd.read_csv(file_path, nrows=0)
        check_df.columns = check_df.columns.str.strip()
        has_target = self._resolve_target_column(check_df) is not None
        unique_labels = np.unique(y)

        if has_target and len(unique_labels) >= 2:
            # Stratified split for classification
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state,
                stratify=y
            )
            if balance:
                X_train, y_train = self.balance_data(X_train, y_train, random_state=random_state)
        else:
            # Random split for unsupervised/single-class
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=test_size, random_state=random_state
            )

        return {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test,
            'feature_names': feature_names,
            'total_records': len(df),
        }

