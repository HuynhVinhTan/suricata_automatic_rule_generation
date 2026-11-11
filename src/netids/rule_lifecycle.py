"""Fail-closed, review-only lifecycle for isolated Suricata rule candidates."""
from __future__ import annotations
import hashlib, json, os, re, tempfile
from datetime import datetime, timezone
from pathlib import Path
from netids.rulegen import REJECTED_SIDS

class LifecycleError(ValueError): pass
_SHA=re.compile(r"^[0-9a-f]{64}$"); _RUN=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TRANSITIONS={"PROPOSED":{"VALIDATING","REJECTED","FAILED"},"VALIDATING":{"VALIDATED_FOR_REVIEW","REJECTED","FAILED"},"VALIDATED_FOR_REVIEW":{"AWAITING_APPROVAL","REJECTED","FAILED"},"AWAITING_APPROVAL":{"APPROVED_FOR_ISOLATED_LAB","REJECTED","FAILED"},"APPROVED_FOR_ISOLATED_LAB":{"STAGED_IN_ISOLATED_LAB","ROLLED_BACK","FAILED"},"STAGED_IN_ISOLATED_LAB":{"ACTIVE_IN_ISOLATED_LAB","ROLLED_BACK","FAILED"},"ACTIVE_IN_ISOLATED_LAB":{"ROLLED_BACK","FAILED"},"REJECTED":set(),"ROLLED_BACK":set(),"FAILED":set()}
def _sha(value): return hashlib.sha256(value.encode("utf-8")).hexdigest()
def _when(value):
    try: return datetime.fromisoformat(value.replace("Z","+00:00"))
    except (AttributeError,ValueError) as exc: raise LifecycleError("Invalid authorization timestamp") from exc
def _canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"))

class RuleLifecycle:
    def __init__(self,audit_path:Path,*,isolated_root:Path=None,existing_sids=()):
        self.audit_path=Path(audit_path); self.isolated_root=Path(isolated_root or self.audit_path.parent/"isolated-lab").resolve(); self.existing_sids=set(existing_sids)
        self.isolated_root.mkdir(parents=True,exist_ok=True)
    def _audit(self,event,candidate,**details):
        self.audit_path.parent.mkdir(parents=True,exist_ok=True); previous="0"*64; sequence=0
        if self.audit_path.exists():
            lines=self.audit_path.read_text(encoding="utf-8").splitlines()
            if lines:
                last=json.loads(lines[-1]); sequence=last["sequence"]; previous=last["record_hash"]
        record={"sequence":sequence+1,"previous_record_hash":previous,"event":event,"candidate_id":candidate.get("candidate_id"),**details}
        record["record_hash"]=_sha(_canonical(record)+previous)
        with self.audit_path.open("a",encoding="utf-8") as stream: stream.write(_canonical(record)+"\n")
    def create_candidate(self,candidate):
        required=("run_id","pcap_sha256","model_sha256","calibration_sha256","sid","rule","rule_sha256")
        if any(key not in candidate for key in required): raise LifecycleError("Missing candidate provenance")
        if not _RUN.fullmatch(candidate["run_id"]): raise LifecycleError("Invalid run_id")
        if any(not isinstance(candidate[key],str) or not _SHA.fullmatch(candidate[key]) for key in ("pcap_sha256","model_sha256","calibration_sha256","rule_sha256")): raise LifecycleError("Invalid provenance hash")
        sid=candidate["sid"]
        if type(sid) is not int or not 1<=sid<=4294967295: raise LifecycleError("Invalid SID")
        if sid in REJECTED_SIDS: raise LifecycleError("rejected historical SID")
        if sid in self.existing_sids: raise LifecycleError("Conflicting SID")
        if candidate["rule_sha256"]!=_sha(candidate["rule"]): raise LifecycleError("Rule hash mismatch")
        if any(candidate.get(key) is not False for key in ("approved","deployable","deployed")): raise LifecycleError("Candidate safety flags must be false")
        result=dict(candidate); result.update({"candidate_id":_sha(f"{candidate['run_id']}:{sid}:{candidate['rule_sha256']}"),"state":"PROPOSED"}); self._audit("candidate_created",result,state="PROPOSED"); return result
    def transition(self,candidate,state):
        current=candidate.get("state")
        if state not in _TRANSITIONS.get(current,set()): raise LifecycleError(f"Invalid lifecycle transition: {current}->{state}")
        if state=="VALIDATED_FOR_REVIEW" and "validation" not in candidate: raise LifecycleError("Authenticated replay evidence is required")
        candidate["state"]=state; self._audit("state_transition",candidate,from_state=current,to_state=state); return candidate
    def record_validation(self,candidate,evidence):
        if candidate.get("state")!="VALIDATING": raise LifecycleError("Candidate is not validating")
        required={"candidate_id":"candidate_id","run_id":"run_id","sid":"sid","rule_sha256":"rule_sha256","pcap_sha256":"pcap_sha256","model_sha256":"model_sha256","calibration_sha256":"calibration_sha256"}
        if any(evidence.get(key)!=candidate[field] for key,field in required.items()): raise LifecycleError("Validation provenance mismatch")
        if not all(evidence.get(key) is True for key in ("syntax_authenticated","attack_replay_passed","normal_replay_passed")): raise LifecycleError("Authenticated attack and normal replay evidence is required")
        if type(evidence.get("threshold")) is not int or evidence["threshold"]<1: raise LifecycleError("Invalid validation threshold")
        if evidence.get("normal_false_positive_count",0)!=0: raise LifecycleError("Normal replay false positives are not allowed")
        candidate["validation"]=_canonical(evidence); self._audit("validation_recorded",candidate,validation=evidence); self.transition(candidate,"VALIDATED_FOR_REVIEW"); return candidate
    def approve(self,candidate,authorization,authorization_verifier):
        if candidate.get("state")!="AWAITING_APPROVAL": raise LifecycleError("Candidate is not awaiting approval")
        fields={"candidate_id":"candidate_id","run_id":"run_id","sid":"sid","rule_sha256":"rule_sha256"}
        if any(authorization.get(k)!=candidate[v] for k,v in fields.items()): raise LifecycleError("Authorization provenance mismatch")
        if authorization.get("environment")!="isolated-lab" or authorization.get("operation") not in ("stage","activate"): raise LifecycleError("Invalid authorization scope")
        if not authorization.get("approver_identity"): raise LifecycleError("Approver identity is required")
        now=datetime.now(timezone.utc); approved=_when(authorization.get("approved_at")); expires=_when(authorization.get("expires_at"))
        if expires<=approved or expires<=now: raise LifecycleError("Authorization is expired")
        if not callable(authorization_verifier) or not authorization_verifier(authorization): raise LifecycleError("Authorization verification failed")
        if "approval" in candidate: raise LifecycleError("Authorization replay rejected")
        candidate["approval"]=dict(authorization); self.transition(candidate,"APPROVED_FOR_ISOLATED_LAB"); return candidate
    def _target(self,path):
        target=Path(path)
        if target.is_symlink(): raise LifecycleError("Unsafe isolated-lab path")
        resolved=target.resolve(); root=self.isolated_root
        if not resolved.is_relative_to(root): raise LifecycleError("Unsafe isolated-lab path")
        return resolved
    def stage(self,candidate,lab_rules_dir,*,activate=False,runtime=None):
        try:
            if candidate.get("state")!="APPROVED_FOR_ISOLATED_LAB": raise LifecycleError("Explicit approval is required before staging")
            if candidate.get("approval",{}).get("rule_sha256")!=candidate.get("rule_sha256"): raise LifecycleError("Approval rule hash mismatch")
            if candidate.get("rule_sha256")!=_sha(candidate.get("rule","")): raise LifecycleError("Rule hash mismatch")
            target=self._target(lab_rules_dir); self._audit("stage_requested",candidate,path=str(target),activate=activate)
            if not activate: return {"status":"dry_run","candidate_id":candidate["candidate_id"],"path":str(target)}
            if candidate["approval"].get("operation")!="activate" or runtime is None: raise LifecycleError("Active isolated-lab installation requires separate owner authorization")
            target.mkdir(parents=True,exist_ok=True); destination=target/(candidate["candidate_id"]+".rules"); previous=destination.read_bytes() if destination.exists() else None
            if not runtime.validate(candidate["rule"]): raise LifecycleError("Isolated runtime syntax validation failed")
            fd,temp=tempfile.mkstemp(dir=target,prefix=".stage-"); os.write(fd,candidate["rule"].encode()); os.close(fd); os.replace(temp,destination)
            candidate["previous_state"]={"path":str(destination),"bytes":previous.hex() if previous is not None else None}; self.transition(candidate,"STAGED_IN_ISOLATED_LAB"); self.transition(candidate,"ACTIVE_IN_ISOLATED_LAB"); return {"status":"active_in_isolated_lab","path":str(destination)}
        except Exception as exc:
            self._audit("stage_failed",candidate,error=str(exc)); raise
    def rollback(self,candidate):
        if candidate.get("state") not in ("ACTIVE_IN_ISOLATED_LAB","STAGED_IN_ISOLATED_LAB"): raise LifecycleError("Nothing staged to roll back")
        previous=candidate.get("previous_state")
        if previous:
            path=Path(previous["path"])
            if previous["bytes"] is None: path.unlink(missing_ok=True)
            else: path.write_bytes(bytes.fromhex(previous["bytes"]))
        self.transition(candidate,"ROLLED_BACK"); self._audit("rollback",candidate); return candidate
