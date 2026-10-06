#!/usr/bin/env python3
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/"test-vectors/generated/protocol-v2-identity-state-v3.json"
OUT=ROOT/"test-vectors/generated/transition-statement-v1.json"
def head(major,n):
 if n<24:return bytes([(major<<5)|n])
 if n<=255:return bytes([(major<<5)|24,n])
 if n<=65535:return bytes([(major<<5)|25])+n.to_bytes(2,"big")
 if n<=0xffffffff:return bytes([(major<<5)|26])+n.to_bytes(4,"big")
 return bytes([(major<<5)|27])+n.to_bytes(8,"big")
def u(n):return head(0,n)
def bs(b):return head(2,len(b))+b
def statement(identity,prev,op_hash,seq,succ):
 return head(5,6)+u(1)+u(1)+u(2)+bs(identity)+u(3)+(b"\xf6" if prev is None else bs(prev))+u(4)+bs(op_hash)+u(5)+u(seq)+u(6)+bs(succ)
def vector(src,id,outid):
 v=next(x for x in src["vectors"] if x["id"]==id)
 op=bytes.fromhex(v["operationBytesHex"]); succ=bytes.fromhex(v["stateHashHex"])
 prev=bytes.fromhex(v["previousStateHashHex"]) if "previousStateHashHex" in v else None
 # Operation header uses fixed semantic identity/sequence; derive from canonical StateBytes:
 state=bytes.fromhex(v["stateBytesHex"])
 # v3 state: a9 01 03 02 58 20 <identity> 03 <sequence...>
 identity=state[6:38]
 # parse sequence from known canonical state by locating label 3 after identity
 i=38
 if state[i]!=3:raise ValueError(id+" state label 3")
 i+=1;b=state[i]
 if b<24:seq=b
 elif b==24:seq=state[i+1]
 elif b==25:seq=int.from_bytes(state[i+1:i+3],"big")
 else:raise ValueError(id+" sequence encoding")
 sb=statement(identity,prev,hashlib.sha256(op).digest(),seq,succ)
 return {"id":outid,"sourceVector":id,"expected":"PASS","statementBytesHex":sb.hex(),"identityHex":identity.hex(),"previousStateHashHex":None if prev is None else prev.hex(),"operationHashHex":hashlib.sha256(op).hexdigest(),"sequence":seq,"successorStateHashHex":succ.hex()}
def main():
 src=json.loads(SRC.read_text())
 valid=[vector(src,"V301","TS01"),vector(src,"V306","TS02"),vector(src,"V314","TS03")]
 base=bytearray.fromhex(valid[1]["statementBytesHex"])
 invalid=[]
 def add(i,e,b):invalid.append({"id":i,"expected":"REJECT","expectedError":e,"statementBytesHex":bytes(b).hex()})
 x=bytearray(base);x[2]=2;add("TSI01","UNSUPPORTED_STATEMENT_VERSION",x)
 add("TSI02","TRUNCATED_STATEMENT",base[:-1])
 add("TSI03","TRAILING_BYTES",base+b"\x00")
 x=bytearray(base);x[0]=0xa5;add("TSI04","MISSING_FIELD",x)
 x=bytearray(base);x[0]=0xa7;add("TSI05","INVALID_MAP_LENGTH",x)
 x=bytearray(base);x[1]=2;add("TSI06","WRONG_FIRST_LABEL",x)
 # CREATE/non-CREATE previous hash semantics are semantic, represented explicitly.
 invalid.append({"id":"TSI07","expected":"REJECT","expectedError":"CREATE_PREDECESSOR_MUST_BE_NULL","sourceVector":"V301","assertion":"CREATE statement previousStateHash MUST be null"})
 invalid.append({"id":"TSI08","expected":"REJECT","expectedError":"NON_CREATE_PREDECESSOR_REQUIRED","sourceVector":"V306","assertion":"non-CREATE statement previousStateHash MUST be 34 bytes"})
 out={"specification":"OI-TS-001 TransitionStatement v1","status":"BYTE-FREEZE CANDIDATE; NOT YET NORMATIVE","validVectors":valid,"invalidVectors":invalid}
 OUT.write_text(json.dumps(out,indent=2)+"\n")
 h=hashlib.sha256(OUT.read_bytes()).hexdigest()
 c=ROOT/"checksums/transition-statement-v1.json.sha256";c.parent.mkdir(exist_ok=True);c.write_text(f"{h}  transition-statement-v1.json\n")
 print("OPENIDENTITY TRANSITIONSTATEMENT V1: GENERATED")
 print("Valid vectors: 3 / 3")
 print("Invalid vectors: 8 / 8")
 print("SHA-256:",h)
if __name__=="__main__":main()
