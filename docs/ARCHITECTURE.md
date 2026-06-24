# System Architecture & Flow

Aegis is divided into layers with decoupled modules isolating pipeline stages.

---

## 1. Topological Components
* **Nginx**: Edge proxy routing static assets, applying rate limits, and proxying backend queries.
* **Gunicorn**: Production WSGI application gateway controlling parallel processing workers.
* **Flask Core**: Application controller handling sessions, blueprint routes, templates, and REST APIs.
* **Database (PostgreSQL)**: Handles persistent transactions and relational models.
* **Scikit-Learn/XGBoost**: Engine computing preprocessors, predictions, and model fits.
* **SHAP (SHapley Additive exPlanations)**: Explains predictions based on game theory concepts.

```
[User Browser] -> [Nginx (Port 80)] -> [Gunicorn (Port 5000)] -> [Flask Application]
                                                                        |
                                                   [PostgreSQL] <-------+-------> [ML Pipeline & SHAP]
```

---

## 2. Threat Scoring Matrix
The scoring system maps traffic risk indicators into a single metric:
$$\text{Threat Score} = 0.3 \times \text{Anomaly Density} + 0.4 \times \text{Model Confidence} + 0.3 \times \text{Feature Deviation}$$

* **Anomaly Density**: Percentage of traffic flagged anomalous relative to total records.
* **Model Confidence**: Average prediction probability assigned to flagged anomalies.
* **Feature Deviation**: Z-score measure representing how far features drift from the mean of normal entries.

---

## 3. Explanations (SHAP Math)
SHAP uses Shapley values to identify individual feature contributions:
$$\phi_i(f, x) = \sum_{S \subseteq N \setminus \{i\}} \frac{|S|!(|N| - |S| - 1)!}{|N|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$

This math measures feature importance without depending on structural biases of a single model type.
