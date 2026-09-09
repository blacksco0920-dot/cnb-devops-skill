#!/usr/bin/env python3
"""Capture native Caddy state read-only and restore it in isolated local Docker."""
import argparse, base64, contextlib, fcntl, hashlib, io, json, os, re, shlex, stat, subprocess, sys, tarfile, tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

LIMIT = 256 * 1024 * 1024
MEMBER_LIMIT = 32 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}")


class NativeCaddyError(ValueError): pass
def require(value, code):
    if not value: raise NativeCaddyError(code)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
def caddy_semver(value):
    found = re.match(r"^v?(\d+\.\d+\.\d+)(?:\s|$)", value)
    require(found is not None, "CADDY_VERSION_INVALID")
    return found.group(1)


_setup_path = Path(__file__).with_name("setup-host.py")
_setup = ModuleType("native_caddy_setup_dependency")
_setup.__file__ = str(_setup_path)
exec(compile(_setup_path.read_bytes(), str(_setup_path), "exec"), _setup.__dict__)
read_safe, strict_json, ssh_command = _setup.read_safe, _setup.strict_json, _setup.ssh_command


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "restore"))
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def safe_output(path):
    path = Path(os.path.abspath(path))
    require(path.parent.resolve(strict=True) == path.parent, "PRIVATE_DIRECTORY_INVALID")
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat(); sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and (not info.st_mode & 0o022 or sticky), "PRIVATE_DIRECTORY_INVALID")
    if os.path.lexists(path):
        info = path.lstat(); require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "PRIVATE_DIRECTORY_INVALID")
    return path


def prepare(args):
    raw = read_safe(args.spec, {0o600}, 1024 * 1024); model = strict_json(raw)
    base = {"schema","target","helper","helper_sha256","evidence_dir"}
    keys = base if args.action == "capture" else base | {"caddy_image","node_image"}
    require(type(model) is dict and set(model) == keys and model["schema"] == "cnb-native-caddy-recovery-spec/v1", "SPEC_INVALID")
    require(all(type(model[k]) is str for k in ("target","helper","helper_sha256","evidence_dir")), "SPEC_INVALID")
    helper = Path(model["helper"]); helper_raw = read_safe(helper, None, 1024 * 1024)
    require(HASH.fullmatch(model["helper_sha256"]) and sha(helper_raw) == model["helper_sha256"] and b"\r" not in helper_raw and helper_raw.endswith(b"\n"), "HELPER_PIN_INVALID")
    if args.action == "restore":
        require(all(type(model[k]) is str and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", model[k]) for k in ("caddy_image","node_image")), "IMAGE_PIN_INVALID")
    target_path = Path(model["target"]); target_raw = read_safe(target_path, {0o600}, 1024 * 1024); target = strict_json(target_raw)
    require(type(target) is dict and set(target) == {"host","port","user","identity_file","known_hosts_file"} and target["user"] in ("root","ubuntu") and type(target["port"]) is int, "TARGET_INVALID")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target["host"]) is not None and 1 <= target["port"] <= 65535, "TARGET_INVALID")
    for key, modes in (("identity_file", {0o400,0o600}), ("known_hosts_file", {0o400,0o600,0o644})):
        require(Path(target[key]).is_absolute(), "TARGET_INVALID"); read_safe(target[key], modes, 1024 * 1024)
    evidence = safe_output(Path(model["evidence_dir"]))
    binding = sha(canonical({"target_sha256":sha(target_raw),"target_files":{k:sha(read_safe(target[k], {0o400,0o600,0o644}, 1024*1024)) for k in ("identity_file","known_hosts_file")},"helper_sha256":sha(helper_raw),"evidence_dir":str(evidence)}))
    return SimpleNamespace(args=args, spec=model, spec_raw=raw, target=target, target_sha256=sha(target_raw), helper_raw=helper_raw, evidence_dir=evidence, binding=binding)


def validate_archive(raw):
    require(0 < len(raw) <= LIMIT, "ARCHIVE_INVALID"); seen=set(); total=0; files={}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
            for item in stream:
                require(item.isfile() and not item.issym() and not item.islnk() and item.name not in seen, "ARCHIVE_INVALID")
                path=Path(item.name); require(not path.is_absolute() and ".." not in path.parts and len(path.parts)>=2 and path.parts[0] in ("config","data"), "ARCHIVE_INVALID")
                require(0 <= item.size <= MEMBER_LIMIT and item.mode == 0o600 and item.uid == 0 and item.gid == 0, "ARCHIVE_INVALID")
                total += item.size; require(total <= LIMIT and len(seen) < 4096, "ARCHIVE_INVALID"); seen.add(item.name)
                body=stream.extractfile(item).read(); require(len(body)==item.size, "ARCHIVE_INVALID"); files[item.name]=body
    except (tarfile.TarError, OSError) as error: raise NativeCaddyError("ARCHIVE_INVALID") from error
    require("config/Caddyfile" in files and any(n.startswith("data/") for n in files), "ARCHIVE_INVALID")
    return files


def archive_files(files):
    out=io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in sorted(files.items()):
            item=tarfile.TarInfo(name); item.size=len(raw); item.mode=0o600; item.uid=item.gid=0; item.uname=item.gname="root"; stream.addfile(item, io.BytesIO(raw))
    return out.getvalue()


ROOT_CAPTURE = r'''
import base64,glob,hashlib,io,json,os,re,shlex,ssl,stat,sys,tarfile
from pathlib import Path
from types import ModuleType
def bad(): raise ValueError('CAPTURE_INVALID')
def sh(b): return hashlib.sha256(b).hexdigest()
def canon(v): return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
try:
 req=json.loads(sys.stdin.buffer.read(2*1024*1024+1)); helper=base64.b64decode(req['helper'],validate=True)
 if len(helper)>1024*1024 or sh(helper)!=req['helper_sha256'] or b'\r' in helper or not helper.endswith(b'\n'): bad()
 mod=ModuleType('reviewed_native_caddy_helper'); mod.__file__='/reviewed/configure-native-caddy.py'; exec(compile(helper,mod.__file__,'exec'),mod.__dict__)
 inv1=mod.inventory(); paths=['/etc/caddy/Caddyfile']
 for site in inv1['sites']: paths += [site['path'],f"/opt/cnb-devops/{site['project']}/{site['environment']}/v1/host-policy.json"]
 # Resolve every file import recursively. Named snippet imports have no matching
 # pathname and remain part of the containing file; file-like imports must match.
 queue=[Path('/etc/caddy/Caddyfile')]; imported=set()
 while queue:
  source=queue.pop(0); resolved=str(source.resolve(strict=True))
  if not (resolved=='/etc/caddy/Caddyfile' or resolved.startswith('/etc/caddy/')): bad()
  if resolved in imported: continue
  imported.add(resolved); body=Path(resolved).read_text(encoding='utf-8')
  for line in body.splitlines():
   match=re.match(r'^\s*import\s+(.+?)\s*$',line)
   if not match: continue
   tokens=shlex.split(match.group(1),comments=True)
   if not tokens: bad()
   token=tokens[0]; candidate=Path(token) if token.startswith('/') else Path(resolved).parent/token
   matches=sorted(glob.glob(str(candidate)))
   file_like=token.startswith('/') or '/' in token or any(x in token for x in ('*','?','[','.'))
   if file_like and not matches: bad()
   for found in matches:
    q=Path(found)
    if not q.is_file() or q.is_symlink(): bad()
    queue.append(q)
 paths += sorted(imported-{str(Path('/etc/caddy/Caddyfile').resolve())}); paths=list(dict.fromkeys(paths))
 data=Path('/var/lib/caddy/.local/share/caddy'); files={}; meta={}; sources={}; count=0; total=0
 def take(p,name):
  global count,total
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fdopen(fd,'rb'); a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or a.st_size>32*1024*1024: bad()
  raw=s.read(a.st_size+1); b=os.fstat(fd); s.close()
  if len(raw)!=a.st_size or any(getattr(a,k)!=getattr(b,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')): bad()
  count+=1; total+=len(raw)
  if count>4096 or total>256*1024*1024: bad()
  files[name]=raw; sources[name]=p; meta[name]={'sha256':sh(raw),'bytes':len(raw),'mode':format(stat.S_IMODE(a.st_mode),'04o'),'uid':a.st_uid,'gid':a.st_gid,'device':a.st_dev,'inode':a.st_ino,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns}
 take(Path(paths[0]),'config/Caddyfile')
 for p in paths[1:]:
  name='config/'+str(Path(p).relative_to('/etc/caddy')) if p.startswith('/etc/caddy/') else 'config/policies/'+Path(p).parts[-4]+'-'+Path(p).parts[-3]+'-host-policy.json'; take(Path(p),name)
 if not data.is_dir() or data.is_symlink(): bad()
 for parent in (data,*data.parents):
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o022: bad()
  if parent==Path('/'): break
 def walk_error(_): bad()
 root_dev=data.lstat().st_dev; dirs_meta={}
 for root,dirs,names in os.walk(data,followlinks=False,onerror=walk_error):
  rs=Path(root).lstat()
  if not stat.S_ISDIR(rs.st_mode) or stat.S_ISLNK(rs.st_mode) or rs.st_dev!=root_dev or rs.st_mode & 0o022: bad()
  dirs_meta[str(Path(root).relative_to(data))]={'device':rs.st_dev,'inode':rs.st_ino,'uid':rs.st_uid,'gid':rs.st_gid,'mode':rs.st_mode,'mtime_ns':rs.st_mtime_ns,'ctime_ns':rs.st_ctime_ns}
  for d in dirs:
   q=Path(root)/d
   if q.is_symlink(): bad()
  for n in names:
   q=Path(root)/n; take(q,'data/caddy/'+str(q.relative_to(data)))
 before_meta=dict(meta); inv2=mod.inventory(); meta2={}
 if canon(inv1)!=canon(inv2): bad()
 current_data=set()
 dirs_meta2={}
 for root,dirs,names in os.walk(data,followlinks=False,onerror=walk_error):
  rs=Path(root).lstat()
  if not stat.S_ISDIR(rs.st_mode) or stat.S_ISLNK(rs.st_mode) or rs.st_dev!=root_dev or rs.st_mode & 0o022: bad()
  dirs_meta2[str(Path(root).relative_to(data))]={'device':rs.st_dev,'inode':rs.st_ino,'uid':rs.st_uid,'gid':rs.st_gid,'mode':rs.st_mode,'mtime_ns':rs.st_mtime_ns,'ctime_ns':rs.st_ctime_ns}
  for d in dirs:
   if (Path(root)/d).is_symlink(): bad()
  for n in names: current_data.add('data/caddy/'+str((Path(root)/n).relative_to(data)))
 if current_data!={name for name in sources if name.startswith('data/caddy/')} or dirs_meta2!=dirs_meta: bad()
 for name,p in sources.items():
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); s=os.fdopen(fd,'rb'); a=os.fstat(fd); raw=s.read(a.st_size+1); b=os.fstat(fd); s.close()
  if not stat.S_ISREG(a.st_mode) or a.st_nlink!=1 or len(raw)!=a.st_size or any(getattr(a,k)!=getattr(b,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')): bad()
  record={'sha256':sh(raw),'bytes':len(raw),'mode':format(stat.S_IMODE(a.st_mode),'04o'),'uid':a.st_uid,'gid':a.st_gid,'device':a.st_dev,'inode':a.st_ino,'mtime_ns':a.st_mtime_ns,'ctime_ns':a.st_ctime_ns}
  if raw!=files[name] or record!=before_meta[name]: bad()
  meta2[name]=record
 final_data=set(); dirs_meta3={}
 for root,dirs,names in os.walk(data,followlinks=False,onerror=walk_error):
  rs=Path(root).lstat()
  if not stat.S_ISDIR(rs.st_mode) or stat.S_ISLNK(rs.st_mode) or rs.st_dev!=root_dev or rs.st_mode & 0o022: bad()
  dirs_meta3[str(Path(root).relative_to(data))]={'device':rs.st_dev,'inode':rs.st_ino,'uid':rs.st_uid,'gid':rs.st_gid,'mode':rs.st_mode,'mtime_ns':rs.st_mtime_ns,'ctime_ns':rs.st_ctime_ns}
  for d in dirs:
   if (Path(root)/d).is_symlink(): bad()
  for n in names: final_data.add('data/caddy/'+str((Path(root)/n).relative_to(data)))
 if final_data!=current_data or dirs_meta3!=dirs_meta2: bad()
 snap={'inventory':inv1,'files':before_meta}
 out=io.BytesIO(); tf=tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT)
 for name,raw in sorted(files.items()):
  ti=tarfile.TarInfo(name); ti.size=len(raw); ti.mode=0o600; ti.uid=ti.gid=0; ti.uname=ti.gname='root'; tf.addfile(ti,io.BytesIO(raw))
 tf.close(); archive=out.getvalue()
 certs={}
 for site in inv1['sites']:
  for domain in site['domains']:
   matches=[(n,v) for n,v in files.items() if n.endswith('/'+domain+'/'+domain+'.crt')]
   if len(matches)!=1: bad()
   text=matches[0][1].decode('ascii'); leaf=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',text,re.S)
   if leaf is None: bad()
   der=ssl.PEM_cert_to_DER_cert(leaf.group(0)); certs[domain]=sh(der)
 version=os.popen('/usr/bin/caddy version').read().strip()
 print(json.dumps({'schema':'cnb-native-caddy-capture/v1','status':'captured','caddy_version':version,'before':snap,'after':{'inventory':inv2,'files':meta2},'tls_certificates':certs,'archive':base64.b64encode(archive).decode()},sort_keys=True))
except Exception:
 print('{"schema":"cnb-native-caddy-capture/v1","status":"failed"}'); sys.exit(1)
'''


def remote_transport(plan):
    request=canonical({"helper":base64.b64encode(plan.helper_raw).decode(),"helper_sha256":sha(plan.helper_raw)})
    remote=["sudo","-n","python3","-c",ROOT_CAPTURE] if plan.target["user"]!="root" else ["python3","-c",ROOT_CAPTURE]
    result=subprocess.run(ssh_command(plan.target,remote),input=request,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,check=False)
    require(result.returncode==0 and len(result.stdout)<=LIMIT*2, "CAPTURE_REMOTE_FAILED")
    return result.stdout


def write_new(path, raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fsync_dir(path.parent)

def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def atomic_write(path, raw):
    fd, temporary = tempfile.mkstemp(prefix="."+path.name+".", dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
        fsync_dir(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def checked_capture(plan):
    state=strict_json(read_safe(plan.evidence_dir/"state.json",{0o600}))
    manifest=strict_json(read_safe(plan.evidence_dir/"capture-manifest.json",{0o600}))
    archive=read_safe(plan.evidence_dir/"capture.tar",{0o600},LIMIT)
    inventory=strict_json(read_safe(plan.evidence_dir/"inventory.json",{0o600}))
    require(state.get("binding")==plan.binding and state.get("capture_manifest_sha256")==sha(canonical(manifest))
            and manifest.get("status")=="captured" and manifest.get("source_unchanged") is True
            and manifest.get("source_before_sha256")==manifest.get("source_after_sha256")
            and manifest.get("source_target_sha256")==plan.target_sha256 and manifest.get("helper_sha256")==sha(plan.helper_raw)
            and manifest.get("archive_sha256")==sha(archive) and manifest.get("source_inventory_sha256")==sha(canonical(inventory)),"SESSION_STATE_INVALID")
    files=validate_archive(archive); require(set(files)==set(manifest.get("files",{})),"SESSION_STATE_INVALID")
    for name,meta in manifest["files"].items(): require(meta.get("sha256")==sha(files[name]) and meta.get("bytes")==len(files[name]),"SESSION_STATE_INVALID")
    return manifest


def capture(plan, transport=remote_transport):
    state=plan.evidence_dir/"state.json"; manifest_path=plan.evidence_dir/"capture-manifest.json"
    if not plan.evidence_dir.exists(): plan.evidence_dir.mkdir(mode=0o700)
    if state.exists():
        current=strict_json(read_safe(state,{0o600})); require(current.get("binding")==plan.binding and current.get("capture_status") in ("capturing","captured"), "SESSION_STATE_INVALID")
        if current["capture_status"]=="captured": return checked_capture(plan)
    else:
        write_new(state,canonical({"schema":"cnb-native-caddy-session/v1","binding":plan.binding,"capture_status":"capturing","restore_status":"pending"}))
    raw=transport(plan); payload=strict_json(raw)
    require(payload.get("schema")=="cnb-native-caddy-capture/v1" and payload.get("status")=="captured" and payload.get("before")==payload.get("after"), "CAPTURE_INVALID")
    inventory=payload["before"]["inventory"]; require(inventory.get("schema")=="cnb-native-caddy-inventory/v1" and inventory.get("status")=="verified", "CAPTURE_INVALID")
    archive=base64.b64decode(payload["archive"],validate=True); files=validate_archive(archive)
    for name,meta in payload["before"]["files"].items(): require(name in files and sha(files[name])==meta["sha256"] and len(files[name])==meta["bytes"], "CAPTURE_INVALID")
    inventory_sha=sha(canonical(inventory)); source_version=payload["caddy_version"]; snapshot_sha=sha(canonical(payload["before"])); manifest={"schema":"cnb-native-caddy-capture-manifest/v1","status":"captured","source_inventory_sha256":inventory_sha,"source_target_sha256":plan.target_sha256,"helper_sha256":sha(plan.helper_raw),"source_caddy_version_full":source_version,"source_caddy_semver":caddy_semver(source_version),"source_before_sha256":snapshot_sha,"source_after_sha256":sha(canonical(payload["after"])),"source_unchanged":True,"archive_sha256":sha(archive),"archive_bytes":len(archive),"files":payload["before"]["files"],"tls_certificates":payload["tls_certificates"]}
    atomic_write(plan.evidence_dir/"capture.tar",archive); atomic_write(plan.evidence_dir/"inventory.json",canonical(inventory)); atomic_write(manifest_path,canonical(manifest)); atomic_write(state,canonical({"schema":"cnb-native-caddy-session/v1","binding":plan.binding,"capture_status":"captured","restore_status":"pending","capture_manifest_sha256":sha(canonical(manifest))}))
    return manifest


def docker(args, data=None, timeout=120):
    try: return subprocess.run(["docker",*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=True).stdout
    except (OSError,subprocess.SubprocessError) as error: raise NativeCaddyError("DOCKER_FAILED") from error

def verify_materialized(files, root):
    for name, raw in files.items(): require(read_safe(root/name,{0o600},MEMBER_LIMIT)==raw,"RESTORE_FILES_DRIFT")

def inspect_isolated(name, plan, restore_dir, require_stopped=False):
    model=strict_json(docker(["container","inspect",name]))
    require(type(model) is list and len(model)==1,"ISOLATION_INVALID"); value=model[0]
    mounts={(item.get("Source"),item.get("Destination"),item.get("RW")) for item in value.get("Mounts",[])}
    expected={(str(restore_dir/"config"),"/etc/caddy",False),(str(restore_dir/"data"),"/data",True)}
    require(value.get("Config",{}).get("Image")==plan.spec["caddy_image"] and value.get("HostConfig",{}).get("NetworkMode")=="none"
            and value.get("HostConfig",{}).get("PortBindings") in (None,{}) and mounts==expected
            and (not require_stopped or value.get("State",{}).get("Running") is False),"ISOLATION_INVALID")
    return value

@contextlib.contextmanager
def session_lock(plan):
    plan.evidence_dir.parent.mkdir(parents=True,exist_ok=True)
    path=plan.evidence_dir.parent/("."+plan.evidence_dir.name+".lock")
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX); yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)


def restore(plan):
    state_path=plan.evidence_dir/"state.json"; state=strict_json(read_safe(state_path,{0o600})); require(state.get("binding")==plan.binding and state.get("capture_status")=="captured", "SESSION_STATE_INVALID")
    receipt_path=plan.evidence_dir/"gateway-recovery-receipt.json"
    manifest=checked_capture(plan); restore_binding=sha(canonical({"manifest_sha256":sha(canonical(manifest)),"caddy_image":plan.spec["caddy_image"],"node_image":plan.spec["node_image"]}))
    if state.get("restore_status")=="verified":
        raw=read_safe(receipt_path,{0o600}); require(state.get("restore_binding")==restore_binding and state.get("recovery_receipt_sha256")==sha(raw),"SESSION_STATE_INVALID")
        archive=read_safe(plan.evidence_dir/"capture.tar",{0o600},LIMIT); verify_materialized(validate_archive(archive),plan.evidence_dir/"restore")
        inspect_isolated(state.get("restore_container_name"),plan,plan.evidence_dir/"restore",True); return strict_json(raw)
    require(state.get("restore_status") in ("pending","restoring") and state.get("restore_binding",restore_binding)==restore_binding,"SESSION_STATE_INVALID")
    state["restore_status"]="restoring"; state["restore_binding"]=restore_binding; atomic_write(state_path,canonical(state))
    archive=read_safe(plan.evidence_dir/"capture.tar",{0o600},LIMIT); files=validate_archive(archive)
    version=docker(["run","--rm","--network=none","--pull=never",plan.spec["caddy_image"],"caddy","version"]).decode().strip(); require(caddy_semver(version)==manifest["source_caddy_semver"],"CADDY_VERSION_MISMATCH")
    restore_dir=plan.evidence_dir/"restore"; restore_dir.mkdir(mode=0o700,exist_ok=True)
    for name,raw in files.items():
        path=restore_dir/name; path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if path.exists(): require(read_safe(path,{0o600},MEMBER_LIMIT)==raw,"RESTORE_FILES_DRIFT")
        else: write_new(path,raw)
    name="cnb-native-caddy-"+manifest["archive_sha256"][:20]
    require(state.get("restore_container_name",name)==name,"SESSION_STATE_INVALID"); state["restore_container_name"]=name; atomic_write(state_path,canonical(state))
    exists=subprocess.run(["docker","container","inspect",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False).returncode==0
    if exists:
        previous=inspect_isolated(name,plan,restore_dir); require(previous["State"]["Running"] is False,"ISOLATION_INVALID"); docker(["start",name])
    else: cid=docker(["run","-d","--name",name,"--network=none","--pull=never","--restart=no","-v",str(restore_dir/"config")+":/etc/caddy:ro","-v",str(restore_dir/"data")+":/data",plan.spec["caddy_image"],"caddy","run","--config","/etc/caddy/Caddyfile"]).decode().strip()
    running=inspect_isolated(name,plan,restore_dir); require(running.get("State",{}).get("Running") is True,"ISOLATION_INVALID"); cid=running.get("Id"); require(type(cid) is str and re.fullmatch(r"[0-9a-f]{64}",cid),"ISOLATION_INVALID")
    domains=sorted(manifest["tls_certificates"])
    js="""const http=require('http'),tls=require('tls'),crypto=require('crypto');let ds=JSON.parse(process.argv[1]);const stable=x=>Array.isArray(x)?x.map(stable):(x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,stable(x[k])])):x);function admin(){return new Promise((ok,no)=>http.get('http://127.0.0.1:2019/config/',r=>{let b='';r.on('data',x=>b+=x);r.on('end',()=>ok(crypto.createHash('sha256').update(JSON.stringify(stable(JSON.parse(b)))+'\\n').digest('hex')))}).on('error',no))}function probe(d){return new Promise((ok,no)=>{let s=tls.connect({host:'127.0.0.1',port:443,servername:d,rejectUnauthorized:false},()=>{let h=crypto.createHash('sha256').update(s.getPeerCertificate(true).raw).digest('hex');s.write('HEAD / HTTP/1.1\\r\\nHost: '+d+'\\r\\nConnection: close\\r\\n\\r\\n');let b='';s.on('data',x=>b+=x);s.on('end',()=>ok([d,{certificate_sha256:h,http_status:Number((b.match(/^HTTP\\/\\S+ (\\d{3})/)||[])[1]||0)}]))});s.on('error',no)})}async function check(){let last;for(let i=0;i<40;i++){try{return await Promise.all([admin(),Promise.all(ds.map(probe))])}catch(e){last=e;await new Promise(r=>setTimeout(r,250))}}throw last}check().then(([r,t])=>process.stdout.write(JSON.stringify({running_sha256:r,tls:Object.fromEntries(t)}))).catch(e=>{console.error(e.message);process.exit(1)})"""
    js=js.replace("const http=require('http')", "const http=require('http');const deadline=setTimeout(()=>process.exit(1),9500);deadline.unref()")
    js=js.replace("s.on('error',no)", "s.setTimeout(1000,()=>s.destroy(new Error('tls timeout')));s.on('error',no)")
    try: observed=strict_json(docker(["run","--rm","--network=container:"+cid,"--pull=never",plan.spec["node_image"],"node","-e",js,json.dumps(domains)],timeout=12))
    finally: docker(["stop",cid])
    require(observed.get("running_sha256")==strict_json(read_safe(plan.evidence_dir/"inventory.json",{0o600}))["running_sha256"],"CONFIG_RESTORE_MISMATCH")
    require({d:v["certificate_sha256"] for d,v in observed.get("tls",{}).items()}==manifest["tls_certificates"],"TLS_RESTORE_MISMATCH")
    inspect=inspect_isolated(name,plan,restore_dir,True)
    receipt={"schema":"cnb-native-caddy-recovery/v1","status":"verified","source_inventory_sha256":manifest["source_inventory_sha256"],"source_target_sha256":plan.target_sha256,"source_unchanged":True,"config_restored":True,"tls_restored":True,"isolated":True,"capture":{"manifest_sha256":sha(canonical(manifest)),"source_before_sha256":manifest["source_before_sha256"],"source_after_sha256":manifest["source_after_sha256"],"archive_sha256":manifest["archive_sha256"],"archive_bytes":manifest["archive_bytes"],"files":manifest["files"],"source_caddy_version_full":manifest["source_caddy_version_full"],"source_caddy_semver":manifest["source_caddy_semver"]},"restore":{"caddy_image":plan.spec["caddy_image"],"node_image":plan.spec["node_image"],"caddy_version_full":version,"caddy_semver":caddy_semver(version),"container_id_sha256":sha(cid.encode()),"running_sha256":observed["running_sha256"],"tls":observed["tls"],"upstreams_restored":False,"http_502_acceptable":True}}
    raw_receipt=canonical(receipt); atomic_write(receipt_path,raw_receipt); state["restore_status"]="verified"; state["recovery_receipt_sha256"]=sha(raw_receipt); atomic_write(state_path,canonical(state)); return receipt


def main(argv=None):
    args=parse_args(argv); plan=prepare(args)
    if not args.apply:
        print(json.dumps({"schema":"cnb-native-caddy-session-result/v1","status":"preview","action":args.action,"source_target_sha256":plan.target_sha256,"helper_sha256":sha(plan.helper_raw),"evidence_dir":str(plan.evidence_dir)},sort_keys=True)); return
    with session_lock(plan): result=capture(plan) if args.action=="capture" else restore(plan)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    try: main()
    except NativeCaddyError as error:
        print(json.dumps({"schema":"cnb-native-caddy-session-result/v1","status":"stopped_review_required","code":str(error)},sort_keys=True)); raise SystemExit(1)
