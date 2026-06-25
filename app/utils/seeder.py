import os
import json
import hashlib
from datetime import datetime, timedelta, timezone
from flask import current_app
from app.extensions import db
from app.models.user import User
from app.models.dataset import Dataset
from app.models.analysis import Analysis

def seed_database():
    """
    Seeds the database with a default admin user 'replica' and some 
    completed analyses if the database is currently empty.
    """
    try:
        # Create all tables if they don't exist yet
        db.create_all()
        
        # 1. Ensure the default user 'replica' exists
        replica = User.query.filter_by(username='replica').first()
        if not replica:
            replica = User(
                username='replica',
                email='admin@replica.security',
                role='admin',
                is_active=True
            )
            replica.set_password('replica123!')
            db.session.add(replica)
            db.session.commit()
            print("[SEED] Default admin user 'replica' created successfully.")
        
        # 2. Check if we need to seed datasets and analyses
        dataset = Dataset.query.filter_by(user_id=replica.id).first()
        analysis_count = Analysis.query.filter_by(user_id=replica.id).count()
        if not dataset or analysis_count < 3:
            print("[SEED] Seeding demo datasets and analysis history...")
            
            # Setup path for a demo dataset file
            filename = "demo_network_traffic.csv"
            upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            
            # Write a simple demo dataset CSV to disk if not present
            csv_content = (
                "duration,protocol_type,src_bytes,dst_bytes,wrong_fragment,urgent,hot,num_failed_logins,label\n"
                "0.1,tcp,250,4500,0,0,0,0,0\n"
                "0.5,udp,45,120,0,0,0,0,0\n"
                "0.05,tcp,1024,0,0,0,0,0,0\n"
                "1.2,icmp,0,0,0,0,0,0,1\n"
                "0.0,tcp,0,0,0,0,0,0,1\n"
                "0.01,tcp,5600,80,0,0,0,0,0\n"
                "3.5,udp,120,0,0,0,0,0,0\n"
                "0.8,tcp,340,1024,0,0,0,0,0\n"
                "0.2,tcp,1050,0,0,0,0,0,0\n"
                "0.15,tcp,140,300,0,0,0,0,1\n"
            )
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(csv_content)
            
            # Compute file hash
            file_hash = hashlib.sha256(csv_content.encode("utf-8")).hexdigest()
            
            if not dataset:
                # Create the Dataset database record
                dataset = Dataset(
                    user_id=replica.id,
                    filename=filename,
                    original_filename="mock_traffic_dataset.csv",
                    file_hash=file_hash,
                    file_size=len(csv_content),
                    row_count=10,
                    column_count=9,
                    columns_list=json.dumps(["duration", "protocol_type", "src_bytes", "dst_bytes", "wrong_fragment", "urgent", "hot", "num_failed_logins", "label"]),
                    status='validated'
                )
                db.session.add(dataset)
                db.session.commit()
            
            # 3. Create simulated historical analysis runs for the trend chart
            now = datetime.now(timezone.utc)
            models = ['random_forest', 'xgboost', 'isolation_forest']
            
            # Seed 5 historical analysis records spaced over the last 5 days
            for i in range(5):
                day_offset = 4 - i
                analysis_date = now - timedelta(days=day_offset, hours=2)
                
                # Vary anomaly count and threat score to create a realistic trend
                anomalies = 12 + (i * 7) % 15
                threat_score = 15.0 + (i * 12.5) % 45.0
                model = models[i % len(models)]
                
                # Mock feature importance rankings
                feat_imp = {
                    "src_bytes": 0.35 - (i * 0.02),
                    "dst_bytes": 0.28 + (i * 0.01),
                    "duration": 0.18,
                    "num_failed_logins": 0.10 + (i * 0.01),
                    "hot": 0.09 - (i * 0.01)
                }
                
                # Mock SHAP summary values
                shap_sum = {
                    "src_bytes": [0.12, -0.05, 0.24, -0.1],
                    "dst_bytes": [0.08, -0.02, 0.18, -0.05],
                    "duration": [0.05, -0.01, 0.12, -0.02],
                    "num_failed_logins": [0.03, 0.0, 0.09, 0.0]
                }
                
                # Mock prediction distribution
                pred_data = {
                    "predictions": [0, 0, 0, 1, 1, 0, 0, 0, 0, 1],
                    "confusion_matrix": [[240 - i*5, 5 + i], [3, 52 - i]],
                    "roc_curve": {"fpr": [0.0, 0.02, 1.0], "tpr": [0.0, 0.95, 1.0], "auc": 0.98 + i*0.003},
                    "attack_distribution": {
                        "Normal": 245 - i*10,
                        "Port Scan": 12 + i*4,
                        "DDoS": 18 + i*2,
                        "Brute Force": 5 + i,
                        "Web Attack": 10 + i
                    }
                }
                
                history_run = Analysis(
                    dataset_id=dataset.id,
                    user_id=replica.id,
                    model_type=model,
                    accuracy=0.97 + (i * 0.005),
                    precision_score=0.96 + (i * 0.007),
                    recall=0.95 + (i * 0.006),
                    f1_score=0.96 + (i * 0.006),
                    roc_auc=0.98 + (i * 0.003),
                    total_records=290 + i*10,
                    anomalies_detected=anomalies,
                    threat_score=round(threat_score, 1),
                    shap_summary=json.dumps(shap_sum),
                    feature_importance=json.dumps(feat_imp),
                    predictions_data=json.dumps(pred_data),
                    status='completed',
                    started_at=analysis_date - timedelta(minutes=5),
                    completed_at=analysis_date,
                    created_at=analysis_date
                )
                db.session.add(history_run)
            
            db.session.commit()
            print("[SEED] Successfully seeded demo dataset and analysis history.")
            
    except Exception as e:
        db.session.rollback()
        print(f"[SEED] Error occurred during database seeding: {str(e)}")
