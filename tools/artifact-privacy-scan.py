#!/usr/bin/env python3
"""Binary-safe privacy gate for image archives, package archives and exact trees.

Reads every layer (including deleted files), metadata, nested tar/zip and gzip/xz
payloads without extracting paths. Findings contain identities/counts, never
matched values. Coverage errors are failures, not clean results. This is a
pattern/known-value gate, not a claim that screenshots or arbitrary secrets have
been exhaustively audited. Exact path+SHA256+family+count classifications only.
"""
import argparse, bz2, gzip, hashlib, io, json, lzma, pathlib, re, sys, tarfile, zipfile

PATTERNS = {
    'private-key-block': rb'-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY-----',
    'password-uri': rb'postgres(?:ql)?://[^\s:/"\']+:[^\s@"\']{4,}@[^\s"\']+',
    'do-password': rb'\bAVNS_[A-Za-z0-9_-]{12,}',
    'do-token': rb'\bdop_v1_[a-f0-9]{64}\b',
    'npm-token': rb'\bnpm_[A-Za-z0-9]{30,}\b',
    'github-fine-grained-token': rb'\bgithub_pat_[A-Za-z0-9_]{40,}\b',
    'extended-private-key': rb'\b[xyz]prv[1-9A-HJ-NP-Za-km-z]{80,}\b',
    'credential-assignment': rb'\b(?:PGPASSWORD|POLICYVAULT_PG_PASSWORD|[A-Z_]{0,60}(?:API_TOKEN|SECRET_KEY|PRIVATE_KEY|WEBHOOK_SECRET))\s{0,4}=\s{0,4}["\']?(?!\$|<)[A-Za-z0-9+/_=.:-]{12,256}',
    'github-token': rb'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    'aws-key': rb'\bAKIA[0-9A-Z]{16}\b',
    'slack-token': rb'\bxox[baprs]-[A-Za-z0-9-]{10,}',
    'jwt': rb'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'machine-token': rb'\bpvmk_[A-Za-z0-9_-]{16,}',
    'tunnel-secret': rb'"TunnelSecret"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
    'private-key-json': rb'"(?:secret|privateKey|private_key|priv|secretHex|seed|mnemonic|xprv|walletSecret)"\s*:\s*"[0-9a-fA-F]{64}"',
    'private-worktree': rb'\.claude/worktrees/|\\wsl\.localhost\\',
    'operator-path': rb'(?:/home|/Users)/(?!(?:pv|node)(?:/|\b))[A-Za-z0-9_.-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9_.-]+\\',
    'canary': rb'PV-CANARY-SECRET',
}
PATTERNS = {k: re.compile(v) for k,v in PATTERNS.items()}
FORBIDDEN_PATH = re.compile(r'(^|/)\.git(/|$)|POLICYVAULT_CONTINUATION_NOTES|DIRECTIVE.*\.md|docs\.zip|(^|/)data(-mainnet)?/(vaults|requests|claims|receipts|audit|orgs)|(^|/)keys/|(^|/)wallets/|(^|/)secrets/|(^|/)backups/|\.env$|\.env\.|staging\.env$|id_rsa|id_ed25519|\.pem$|\.ppk$|cloudflared-.*\.json|(^|/)\.ssh(/|$)|(^|/)\.config/gh(/|$)|(^|/)\.aws(/|$)|(^|/)\.kube(/|$)')
BENIGN_PATH = re.compile(r'^etc/ssl/certs/[^/]+\.pem$|^usr/lib/ssl/cert\.pem$|^var/backups/$')

def sha(b): return hashlib.sha256(b).hexdigest()
def forbidden_path(name):
    if BENIGN_PATH.fullmatch(name):return False
    if re.fullmatch(r'app/sdk/node_modules/.+/keys/[^/]*',name):
        # Only the known module-directory name collision is benign; an .env,
        # private.pem, .ssh or other forbidden component STILL refuses.
        name=name.replace('/keys/','/module-key-shim/')
    return bool(FORBIDDEN_PATH.search(name))

class Scanner:
    def __init__(self, classifications=None, known=None, max_bytes=2_000_000_000):
        self.allowed = classifications or []
        self.known = known or {}
        self.max_bytes = max_bytes
        self.findings, self.classified, self.errors = [], [], []
        self.stats = dict(files=0, bytes=0, binaryFiles=0, archives=0, compressedPayloads=0, metadata=0)
        self.identities = []
    def inspect(self, name, data, *, metadata=False):
        self.stats['bytes'] += len(data)
        if self.stats['bytes'] > self.max_bytes: raise ValueError('expanded scan byte limit exceeded')
        self.stats['metadata' if metadata else 'files'] += 1
        if b'\0' in data: self.stats['binaryFiles'] += 1
        digest = sha(data)
        self.identities.append((name, digest))
        counts = {k:len(p.findall(data)) for k,p in PATTERNS.items() if p.search(data)}
        for label,value in self.known.items():
            n=data.count(value.encode())
            if n: counts['known:'+label]=n
        if forbidden_path(name): counts['forbidden-path']=1
        for family,count in counts.items():self.record(name,digest,family,count)
    def boundary(self,data,offset,name):
        # Match only values crossing a raw-region boundary; ordinary findings
        # retain their existing byte/path classifications without duplication.
        span=max(512,max((len(v.encode()) for v in self.known.values()),default=0))
        start=max(0,offset-span);body=data[start:offset+span];cut=offset-start
        counts={k:sum(m.start()<cut<m.end() for m in p.finditer(body)) for k,p in PATTERNS.items()}
        for label,value in self.known.items():counts['known:'+label]=sum(m.start()<cut<m.end() for m in re.finditer(re.escape(value.encode()),body))
        for family,count in counts.items():
            if count:self.record(name,sha(body),family,count)
    def record(self,name,digest,family,count):
        row={'path':name,'sha256':digest,'family':family,'count':count}
        if any(all(a.get(k)==v for k,v in row.items()) for a in self.allowed):self.classified.append(row)
        else:self.findings.append(row)
    def decompress(self,data,name):
        self.inspect(name+'#compressed-metadata',data,metadata=True)
        decoder=gzip.GzipFile(fileobj=io.BytesIO(data)) if data.startswith(b'\x1f\x8b') else (bz2.BZ2File(io.BytesIO(data)) if data.startswith(b'BZh') else lzma.LZMAFile(io.BytesIO(data)))
        with decoder:decoded=decoder.read(min(512_000_001,self.max_bytes+1))
        if len(decoded)>512_000_000:raise ValueError('expanded payload limit exceeded')
        self.stats['compressedPayloads']+=1
        return decoded
    def archive(self, data, prefix='', depth=0, image_outer=False):
        if depth>6: raise ValueError('nested archive depth exceeded')
        # Entry-point .tgz/outer-image headers need the same coverage as nested
        # payloads. Do not let tarfile transparently discard compressed metadata.
        if data.startswith((b'\x1f\x8b',b'\xfd7zXZ\x00',b'BZh')):data=self.decompress(data,prefix)
        tf=tarfile.open(fileobj=io.BytesIO(data),mode='r:')
        self.stats['archives']+=1
        inventory={};cursor=0
        with tf:
            for item in tf:
                name=item.name.removeprefix('./')
                logical=prefix+name
                # Preserve raw header extensions, padding and bytes after EOF;
                # semantic tar metadata alone silently discards those bytes.
                self.inspect(logical+'#tar-header',data[cursor:item.offset_data],metadata=True)
                cursor=item.offset_data+((item.size+511)//512)*512
                self.inspect(logical+'#tar-padding',data[item.offset_data+item.size:cursor],metadata=True)
                for off in {item.offset_data,item.offset_data+item.size,cursor}:self.boundary(data,off,logical+'#tar-boundary-'+str(off))
                if name.startswith('/') or '..' in pathlib.PurePosixPath(name).parts: raise ValueError('unsafe archive member path')
                meta=json.dumps({'path':name,'link':item.linkname,'pax':item.pax_headers,'uname':item.uname,'gname':item.gname},sort_keys=True).encode()
                self.inspect(logical+'#metadata',meta,metadata=True)
                if forbidden_path(name):self.record(logical,sha(meta),'forbidden-path',1)
                if not item.isfile():continue
                if item.size>512_000_000:raise ValueError('single member size limit exceeded')
                body=tf.extractfile(item).read()
                if image_outer:
                    if name in inventory: raise ValueError('duplicate outer archive member')
                    try: obj=json.loads(body) if body[:1] in (b'{',b'[') else None
                    except (ValueError,UnicodeError): obj=None
                    inventory[name]={'bytes':len(body),'sha256':sha(body),'json':obj,'body':body}
                if len(body)!=item.size:raise ValueError('truncated archive member')
                if image_outer and name.startswith('blobs/sha256/') and sha(body)!=name.rsplit('/',1)[1]:raise ValueError('OCI blob digest mismatch')
                # Every blob/layer is read, irrespective of final-rootfs whiteouts.
                if image_outer and (name.startswith('blobs/sha256/') or name.endswith('/layer.tar')):
                    self.payload(body,'',depth+1)
                else:self.payload(body,logical,depth+1)
        self.inspect(prefix+'#tar-trailer',data[cursor:],metadata=True)
        if image_outer:self.validate_image(inventory)
    def validate_image(self,inventory):
        def descriptor(d,kind):
            if not isinstance(d,dict) or not re.fullmatch(r'sha256:[0-9a-f]{64}',str(d.get('digest',''))):raise ValueError('invalid OCI descriptor')
            row=inventory.get('blobs/sha256/'+d['digest'][7:])
            if row is None or row['bytes']!=d.get('size'):raise ValueError('missing OCI referenced blob or size mismatch')
            media=d.get('mediaType','')
            if kind not in media:raise ValueError('unexpected OCI descriptor media type')
            return row
        def layer_tar(row,media,diff_id,present):
            raw=row['body']
            if media in ('application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.nondistributable.v1.tar+gzip'):
                if not raw.startswith(b'\x1f\x8b'):raise ValueError('declared gzip layer has invalid magic')
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:raw=stream.read(512_000_001)
                if len(raw)>512_000_000:raise ValueError('expanded layer limit exceeded')
            elif media not in ('application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.nondistributable.v1.tar'):
                raise ValueError('unsupported image layer media type; scan incomplete')
            # Descriptor hashes alone bind compressed bytes, not valid layer
            # decoding. Every declared layer must be a tar with the config's
            # exact uncompressed diff_id; another valid layer is no substitute.
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tf:
                members=list(tf)
                # Whiteouts remove lower-layer entries irrespective of tar order.
                # Ordinary members are then applied in their own stored order.
                ordered=[i for i in members if i.name.rsplit('/',1)[-1].startswith('.wh.')]+[i for i in members if not i.name.rsplit('/',1)[-1].startswith('.wh.')]
                for item in ordered:
                    name=item.name.removeprefix('./').rstrip('/');anchor='app/server/src/server.js'
                    directory,_,base=name.rpartition('/')
                    if base=='.wh..wh..opq' and (not directory or anchor.startswith(directory+'/')):present=False
                    elif base.startswith('.wh.'):
                        removed=(directory+'/' if directory else '')+base[4:]
                        if anchor==removed or anchor.startswith(removed+'/'):present=False
                    elif name==anchor:present=item.isfile()
                    elif name and anchor.startswith(name+'/') and not item.isdir():present=False
                    if item.isfile():
                        if item.size>512_000_000:raise ValueError('single layer member limit exceeded')
                        if len(tf.extractfile(item).read())!=item.size:raise ValueError('truncated layer member')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}',str(diff_id)) or 'sha256:'+sha(raw)!=diff_id:raise ValueError('image layer diff_id mismatch')
            return present
        if 'index.json' in inventory:
            index=inventory['index.json']['json'];layout=inventory.get('oci-layout',{}).get('json')
            if layout!={'imageLayoutVersion':'1.0.0'} or not isinstance(index,dict) or index.get('schemaVersion')!=2 or not index.get('manifests'):raise ValueError('invalid OCI layout/index')
            for desc in index['manifests']:
                manifest=descriptor(desc,'manifest')['json']
                if not isinstance(manifest,dict) or manifest.get('schemaVersion')!=2 or not manifest.get('layers'):raise ValueError('invalid OCI image manifest')
                config=descriptor(manifest.get('config'),'config')['json']
                if not isinstance(config,dict) or config.get('rootfs',{}).get('type')!='layers' or len(config.get('rootfs',{}).get('diff_ids',[]))!=len(manifest['layers']):raise ValueError('invalid OCI image config/rootfs')
                present=False
                for layer,diff_id in zip(manifest['layers'],config['rootfs']['diff_ids']):present=layer_tar(descriptor(layer,'layer'),layer['mediaType'],diff_id,present)
                if not present:raise ValueError('required app/server/src/server.js absent from referenced final image')
        elif 'manifest.json' in inventory:
            manifests=inventory['manifest.json']['json']
            if not isinstance(manifests,list) or not manifests:raise ValueError('invalid Docker manifest')
            for manifest in manifests:
                if not isinstance(manifest,dict) or not manifest.get('Layers') or manifest.get('Config') not in inventory:raise ValueError('invalid Docker descriptor')
                config=inventory[manifest['Config']]['json']
                if not isinstance(config,dict) or config.get('rootfs',{}).get('type')!='layers' or len(config.get('rootfs',{}).get('diff_ids',[]))!=len(manifest['Layers']):raise ValueError('invalid Docker config/rootfs')
                present=False
                for layer,diff_id in zip(manifest['Layers'],config['rootfs']['diff_ids']):
                    if layer not in inventory:raise ValueError('missing referenced Docker layer')
                    present=layer_tar(inventory[layer],'application/vnd.oci.image.layer.v1.tar',diff_id,present)
                if not present:raise ValueError('required app/server/src/server.js absent from referenced final image')
        else:raise ValueError('archive has no image manifest')
    def payload(self,data,name,depth=0):
        if depth>6:raise ValueError('nested archive depth exceeded')
        # Decode magic-detected compression BEFORE text matching. A malformed
        # compressed stream fails the scan rather than becoming "binary skip".
        compressed=data.startswith(b'\x1f\x8b') or data.startswith(b'\xfd7zXZ\x00') or data.startswith(b'BZh')
        if compressed:
            decoded=self.decompress(data,name)
            # Archive members retain their logical archive boundary.
            try: tarfile.open(fileobj=io.BytesIO(decoded),mode='r:').close()
            except tarfile.ReadError:self.payload(decoded,name+'!decoded',depth+1)
            else:self.archive(decoded,(name+'!/') if name else '',depth)
        elif data.startswith(b'\x28\xb5\x2f\xfd'):
            raise ValueError('zstd payload requires a supported decoder; scan incomplete')
        elif data.startswith(b'PK\x03\x04'):
            self.stats['archives']+=1
            self.inspect(name+'#zip-metadata',data,metadata=True)
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in z.infolist():
                    if member.filename.startswith('/') or '..' in pathlib.PurePosixPath(member.filename).parts:raise ValueError('unsafe ZIP member path')
                    if member.flag_bits&1:raise ValueError('encrypted nested ZIP is uninspectable')
                    if member.is_dir():continue
                    if member.file_size>512_000_000:raise ValueError('ZIP member limit exceeded')
                    self.payload(z.read(member),name+'!/'+member.filename,depth+1)
        else:
            try: tarfile.open(fileobj=io.BytesIO(data),mode='r:').close()
            except tarfile.ReadError:self.inspect(name or '#image-metadata',data,metadata=not name)
            else:self.archive(data,(name+'!/') if name else '',depth)
    def tree(self,root):
        for p in sorted(root.rglob('*')):
            name=p.relative_to(root).as_posix()
            if p.is_symlink():self.inspect(name+'#symlink',str(p.readlink()).encode(),metadata=True)
            elif p.is_file():self.payload(p.read_bytes(),name)
    def result(self):
        return {'schema':'policyvault-artifact-privacy/v2','complete':not self.errors,'pass':not self.findings and not self.errors,'stats':self.stats,'knownValueCount':len(self.known),'identityManifestSha256':sha(json.dumps(self.identities,separators=(',',':')).encode()),'findings':self.findings,'classified':self.classified,'errors':self.errors,'limits':'No claim of complete arbitrary-secret discovery, screenshot-visible content or steganography analysis.'}

def main():
    p=argparse.ArgumentParser(description=__doc__);mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--archive',type=pathlib.Path);mode.add_argument('--image-archive',type=pathlib.Path);mode.add_argument('--tree',type=pathlib.Path);mode.add_argument('--classify-paths',action='store_true')
    p.add_argument('--classifications',type=pathlib.Path);p.add_argument('--known',type=pathlib.Path);args=p.parse_args()
    if args.classify_paths:
        rows=[s.rstrip('\n') for s in sys.stdin if forbidden_path(s.rstrip('\n'))];print('\n'.join(rows)) if rows else None;return int(bool(rows))
    known=json.loads(sys.stdin.read() if str(args.known)=='-' else args.known.read_text()) if args.known else {}
    if any(not isinstance(v,str) or len(v)<8 for v in known.values()):raise ValueError('known values must be strings of at least eight characters')
    s=Scanner(json.loads(args.classifications.read_text()) if args.classifications else None,known)
    subject={}
    try:
        if args.tree:
            if not args.tree.is_dir():raise ValueError('tree does not exist')
            s.tree(args.tree);subject={'kind':'tree'}
        else:
            f=args.image_archive or args.archive;b=f.read_bytes();subject={'kind':'image-archive' if args.image_archive else 'archive','sha256':sha(b),'bytes':len(b)}
            s.archive(b,image_outer=bool(args.image_archive))
    except Exception as e:s.errors.append({'type':type(e).__name__,'reason':str(e)[:150]})
    r=s.result();r['subject']=subject;print(json.dumps(r,indent=2));return 2 if r['errors'] else int(not r['pass'])
if __name__=='__main__':sys.exit(main())
