"""Run inside Python WASIX. Synthesize bounded fixture bytes, not an authorization proof."""
import hashlib, json, sys
proposal=json.load(sys.stdin)
raw=json.dumps(proposal,sort_keys=True,separators=(',',':')).encode('ascii')
print(json.dumps({'body':raw.decode('ascii'),'sha256':hashlib.sha256(raw).hexdigest()},separators=(',',':')))
