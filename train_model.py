"""Download PhiUSIIL from UCI and train a reproducible URL-only Random Forest model."""
from pathlib import Path
import json, sys, warnings
warnings.filterwarnings("ignore")
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from joblib import dump
from src.features import extract_url_features, FEATURE_NAMES

ROOT=Path(__file__).resolve().parent
RAW=ROOT/"data"/"raw"/"PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL=ROOT/"models"/"url_model.joblib"
REPORTS=ROOT/"reports"; REPORTS.mkdir(exist_ok=True)

def obtain_data():
    if RAW.exists(): return pd.read_csv(RAW)
    print("Downloading dataset from UCI (one-time; about 54 MB CSV)...")
    from ucimlrepo import fetch_ucirepo
    ds=fetch_ucirepo(id=967)
    df=pd.concat([ds.data.features,ds.data.targets],axis=1)
    RAW.parent.mkdir(parents=True,exist_ok=True)
    df.to_csv(RAW,index=False)
    return df

def main():
    df=obtain_data()
    url_col=next((c for c in df.columns if c.lower()=="url"),None)
    label_col=next((c for c in df.columns if c.lower()=="label"),None)
    if not url_col or not label_col: raise ValueError("Dataset must include URL and label columns.")
    df=df[[url_col,label_col]].dropna().drop_duplicates(subset=[url_col])
    # PhiUSIIL: 0=phishing, 1=legitimate. Model positive class is phishing=1.
    y=(pd.to_numeric(df[label_col],errors="coerce")==0).astype(int).to_numpy()
    X=np.asarray([extract_url_features(u) for u in df[url_col].astype(str)],dtype=float)
    if len(np.unique(y))!=2: raise ValueError("Training data must contain both classes.")
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.20,random_state=42,stratify=y)
    model=Pipeline([("imputer",SimpleImputer(strategy="median")),
                    ("scale",StandardScaler()),
                    ("classifier",RandomForestClassifier(n_estimators=300,max_depth=22,min_samples_leaf=2,
                       class_weight="balanced_subsample",n_jobs=-1,random_state=42))])
    print(f"Training Random Forest on {len(X_train):,} URLs; testing on {len(X_test):,} held-out URLs...")
    model.fit(X_train,y_train)
    pred=model.predict(X_test); prob=model.predict_proba(X_test)[:,1]
    cm=confusion_matrix(y_test,pred,labels=[0,1])
    metrics={
      "dataset":"UCI PhiUSIIL Phishing URL (Website)","dataset_rows":int(len(df)),
      "train_rows":int(len(X_train)),"test_rows":int(len(X_test)),
      "accuracy":round(float(accuracy_score(y_test,pred)),4),
      "precision":round(float(precision_score(y_test,pred,zero_division=0)),4),
      "recall":round(float(recall_score(y_test,pred,zero_division=0)),4),
      "f1":round(float(f1_score(y_test,pred,zero_division=0)),4),
      "roc_auc":round(float(roc_auc_score(y_test,prob)),4),
      "confusion_matrix":{"tn":int(cm[0,0]),"fp":int(cm[0,1]),"fn":int(cm[1,0]),"tp":int(cm[1,1])},
      "features":FEATURE_NAMES,"positive_class":"phishing","test_split":"Stratified 80/20, random_state=42",
      "note":"Metrics are from a random held-out split of this dataset; they do not guarantee performance on future campaigns or unseen domains."
    }
    MODEL.parent.mkdir(exist_ok=True)
    dump(model,MODEL)
    (REPORTS/"metrics.json").write_text(json.dumps(metrics,indent=2))
    (REPORTS/"classification_report.txt").write_text(classification_report(y_test,pred,target_names=["legitimate","phishing"]))
    print(json.dumps(metrics,indent=2))
    print(f"\nSaved model: {MODEL}\nSaved evaluation: {REPORTS/'metrics.json'}")

if __name__=="__main__": main()
