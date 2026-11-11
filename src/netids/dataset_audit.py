"""Streaming, read-only quality profiling for delimited network datasets."""
from __future__ import annotations
import csv, hashlib, json, math, os, shutil, sqlite3, tempfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

def _json_hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
def _sha256_file(path):
    digest=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""): digest.update(chunk)
    return digest.hexdigest()
def _timestamp_valid(value):
    if not value: return False
    try: datetime.fromisoformat(value.replace("Z", "+00:00")); return True
    except ValueError:
        for pattern in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try: datetime.strptime(value, pattern); return True
            except ValueError: pass
        try: return math.isfinite(float(value))
        except ValueError: return False

def profile_csv(path: Path, output_dir: Path, *, feature_columns=(), label_columns=(), timestamp_columns=()):
    path=Path(path).resolve(strict=True)
    if not path.is_file() or path.is_symlink(): raise ValueError("Dataset must be a regular file")
    output_dir=Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
    feature_columns, label_columns, timestamp_columns=map(tuple,(feature_columns,label_columns,timestamp_columns))
    exact=shutil.disk_usage(output_dir).free >= max(64*1024*1024,path.stat().st_size)
    db_path=db=None; labels=Counter(); missing=Counter(); stats={}; duplicate_values=defaultdict(lambda:{"equal":0,"unequal":0})
    malformed_rows=invalid_timestamps=rows=0; duplicate_column_names=[]; duplicate_rows=contradictory=None; header=[]
    try:
        if exact:
            fd,name=tempfile.mkstemp(prefix="quality-",suffix=".sqlite3",dir=output_dir); os.close(fd); db_path=Path(name); db=sqlite3.connect(db_path)
            db.execute("CREATE TABLE row_hashes (hash TEXT PRIMARY KEY,count INTEGER NOT NULL)")
            db.execute("CREATE TABLE feature_labels (feature_hash TEXT NOT NULL,label TEXT NOT NULL,PRIMARY KEY(feature_hash,label))")
        with path.open("r",encoding="utf-8",newline="") as stream:
            reader=csv.reader(stream)
            try: header=[name.strip() for name in next(reader)]
            except StopIteration: header=[]
            positions=defaultdict(list)
            for index,name in enumerate(header): positions[name].append(index)
            duplicate_column_names=sorted(name for name,indexes in positions.items() if len(indexes)>1)
            for name in feature_columns+label_columns+timestamp_columns:
                if name not in positions: raise ValueError(f"Column not found: {name}")
                if len(positions[name])>1: raise ValueError(f"Ambiguous duplicate column: {name}")
            for values in reader:
                if len(values)!=len(header): malformed_rows+=1; continue
                rows+=1
                for name in duplicate_column_names:
                    vals=[values[index].strip() for index in positions[name]]
                    duplicate_values[name]["equal" if len(set(vals))==1 else "unequal"]+=1
                label="|".join(values[positions[name][0]].strip() for name in label_columns) if label_columns else ""
                if label: labels[label]+=1
                feature=tuple(values[positions[name][0]].strip() for name in feature_columns)
                if db:
                    db.execute("INSERT INTO row_hashes VALUES(?,1) ON CONFLICT(hash) DO UPDATE SET count=count+1",(_json_hash(values),))
                    if feature_columns: db.execute("INSERT OR IGNORE INTO feature_labels VALUES(?,?)",(_json_hash(feature),label))
                for index,value in enumerate(values):
                    if not value.strip(): missing[header[index]]+=1
                for name in feature_columns:
                    value=values[positions[name][0]].strip(); stat=stats.setdefault(name,{"numeric":0,"nan":0,"inf":0,"min":None,"max":None})
                    try:
                        number=float(value)
                        if math.isnan(number): stat["nan"]+=1
                        elif math.isinf(number): stat["inf"]+=1
                        else: stat["numeric"]+=1; stat["min"]=number if stat["min"] is None else min(stat["min"],number); stat["max"]=number if stat["max"] is None else max(stat["max"],number)
                    except ValueError: pass
                for name in timestamp_columns:
                    if not _timestamp_valid(values[positions[name][0]].strip()): invalid_timestamps+=1
        if db:
            duplicate_rows=int(db.execute("SELECT COALESCE(SUM(count-1),0) FROM row_hashes").fetchone()[0])
            contradictory=int(db.execute("SELECT COUNT(*) FROM (SELECT feature_hash FROM feature_labels GROUP BY feature_hash HAVING COUNT(*)>1)").fetchone()[0]); db.commit()
    finally:
        if db: db.close()
        if db_path: db_path.unlink(missing_ok=True)
    report={"audit_status":"COMPLETE" if exact else "PARTIAL","path":str(path),"sha256":_sha256_file(path),"size_bytes":path.stat().st_size,"record_count":rows,"column_count":len(header),"columns":header,"duplicate_column_names":duplicate_column_names,"duplicate_column_values":dict(duplicate_values),"malformed_rows":malformed_rows,"missing_values":dict(sorted(missing.items())),"nan_or_inf":{k:v for k,v in stats.items() if v["nan"] or v["inf"]},"exact_duplicate_rows":duplicate_rows,"contradictory_feature_labels":contradictory,"label_distribution":dict(sorted(labels.items())),"feature_stats":stats,"invalid_timestamps":invalid_timestamps,"timestamp_columns":list(timestamp_columns),"host_identity_columns":[name for name in header if any(token in name.lower() for token in ("ip","host","src","dst"))],"feature_columns":list(feature_columns),"label_columns":list(label_columns),"audit_notes":[] if exact else ["Exact duplicate and contradiction checks skipped because disk budget was unavailable."]}
    (output_dir/"profile.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8"); return report
