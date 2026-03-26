Place trained ML artifacts in this folder:

1) model.pkl
   - A classifier object that supports predict_proba().
2) preprocessor.pkl
   - A fitted transformer with transform().
3) threshold.json (optional)
   - Example: {"optimal_threshold": 0.62}

The app loads these files at runtime for CSV scoring.
