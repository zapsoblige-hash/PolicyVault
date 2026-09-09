"""No Docker/network: hostile archive boundaries and byte-bound classifications."""
import gzip, hashlib, importlib.util, io, json, pathlib, subprocess, sys, tarfile, tempfile, unittest
spec=importlib.util.spec_from_file_location('privacy',pathlib.Path(__file__).with_name('artifact-privacy-scan.py'));p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
def tar(rows):
 b=io.BytesIO()
 with tarfile.open(fileobj=b,mode='w') as f:
  for name,data in rows.items():
   m=tarfile.TarInfo(name);m.size=len(data);f.addfile(m,io.BytesIO(data))
 return b.getvalue()
def image(secret,metadata=b'{}',mutate_layer=None,bad_diff_id=False,missing_app=False,orphan_app=False,delete_app=False,replacement_opaque=False):
 raw=[tar({'app/server/src/server.js':b'module.exports={};','removed.bin':secret}),tar({'.wh.removed.bin':b''})]
 if missing_app:raw[0]=tar({'other-app':b'ok'})
 if delete_app:raw[1]=tar({'app/server/src/.wh.server.js':b''})
 if replacement_opaque:raw[1]=tar({'app/server/src/server.js':b'new app','app/server/src/.wh..wh..opq':b''})
 layers=[gzip.compress(b) for b in raw]
 if mutate_layer:layers[1]=mutate_layer(layers[1])
 config=json.dumps({'rootfs':{'type':'layers','diff_ids':['sha256:'+('0'*64 if bad_diff_id and i==1 else p.sha(b)) for i,b in enumerate(raw)]},'extra':json.loads(metadata)}).encode()
 def desc(b,kind):return {'mediaType':'application/vnd.oci.image.'+kind,'digest':'sha256:'+p.sha(b),'size':len(b)}
 manifest=json.dumps({'schemaVersion':2,'config':desc(config,'config.v1+json'),'layers':[desc(b,'layer.v1.tar+gzip') for b in layers]}).encode()
 index=json.dumps({'schemaVersion':2,'manifests':[desc(manifest,'manifest.v1+json')]}).encode()
 orphan=[gzip.compress(tar({'app/server/src/server.js':b'orphan'}))] if orphan_app else []
 return tar({'oci-layout':b'{"imageLayoutVersion":"1.0.0"}','index.json':index,**{'blobs/sha256/'+p.sha(b):b for b in [*layers,config,manifest,*orphan]}})
class Gate(unittest.TestCase):
 def test_compressed_deleted_binary_secret_fails(self):
  s=p.Scanner();s.archive(image(b'\0'+b'-----BEGIN PRIVATE KEY-----\nfixture'),image_outer=True)
  self.assertTrue(any(r['family']=='private-key-block' for r in s.findings));self.assertFalse(s.result()['pass'])
 def test_metadata_and_known_values_are_not_skipped(self):
  s=p.Scanner(known={'fixture':'only-a-fixture-secret'});s.archive(image(b'ok',json.dumps({'history':'only-a-fixture-secret'}).encode()),image_outer=True)
  self.assertTrue(any(r['family']=='known:fixture' for r in s.findings))
 def test_nested_binary_operator_path(self):
  s=p.Scanner();s.payload(gzip.compress(tar({'wasm':b'\0file=/home/private-builder/work/source.rs\0'})),'bundle.tar.gz')
  self.assertTrue(any(r['path']=='bundle.tar.gz!/wasm' and r['family']=='operator-path' for r in s.findings))
 def test_classification_is_exact_and_does_not_hide_other_families(self):
  body=b'-----BEGIN PRIVATE KEY-----';a={'path':'example','sha256':p.sha(body),'family':'private-key-block','count':1}
  s=p.Scanner([a]);s.inspect('example',body);self.assertTrue(s.result()['pass'])
  for name,data in [('elsewhere',body),('example',body+b'changed'),('example',body+b'\0/home/private-user/source.rs')]:
   s=p.Scanner([a]);s.inspect(name,data);self.assertFalse(s.result()['pass'])
 def test_cli_failed_gate_and_corrupted_oci_exit_nonzero(self):
  with tempfile.TemporaryDirectory(prefix='pv-artifact-gate-') as d:
   f=pathlib.Path(d)/'image.tar'
   for data,code in [(image(b'PV-CANARY-SECRET'),1),(tar({'blobs/sha256/'+'0'*64:b'{}'}),2),(image(b'plain safe fixture'),0)]:
    f.write_bytes(data);r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('artifact-privacy-scan.py')),'--image-archive',str(f)],capture_output=True,text=True)
    self.assertEqual(r.returncode,code,r.stdout);self.assertEqual(json.loads(r.stdout)['pass'],code==0)
 def test_top_level_gzip_metadata_and_image_validation(self):
  with tempfile.TemporaryDirectory(prefix='pv-artifact-gate-') as d:
   f=pathlib.Path(d)/'outer.tgz'
   for payload,mode,code in [(tar({'index.js':b'ok'}),'--archive',1),(image(b'ok'),'--image-archive',1),(tar({'not-image':b'ok'}),'--image-archive',2)]:
    b=io.BytesIO()
    with gzip.GzipFile(fileobj=b,mode='wb',filename='PV-CANARY-SECRET') as z:z.write(payload)
    f.write_bytes(b.getvalue());r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('artifact-privacy-scan.py')),mode,str(f)],capture_output=True,text=True)
    self.assertEqual(r.returncode,code,r.stdout)
    self.assertTrue(any(x['family']=='canary' for x in json.loads(r.stdout)['findings']))
 def test_archive_forbidden_path_classification_is_exact(self):
  data=tar({'prod.env.example':b'example only'})
  initial=p.Scanner();initial.archive(data)
  self.assertTrue(initial.findings)
  s=p.Scanner(initial.findings);s.archive(data);self.assertTrue(s.result()['pass'],s.findings)
  s=p.Scanner(initial.findings);s.archive(tar({'prod.env.example':b'changed'}));self.assertFalse(s.result()['pass'])
 def test_known_stdin_blocks_a_binary_value_without_printing_it(self):
  with tempfile.TemporaryDirectory(prefix='pv-artifact-gate-') as d:
   f=pathlib.Path(d)/'test.tar';value='only-a-private-fixture-value';f.write_bytes(tar({'binary':b'\0'+value.encode()+b'\0'}))
   r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('artifact-privacy-scan.py')),'--archive',str(f),'--known','-'],input=json.dumps({'fixture':value}),capture_output=True,text=True)
   self.assertEqual(r.returncode,1);self.assertNotIn(value,r.stdout+r.stderr)
   self.assertTrue(any(x['family']=='known:fixture' for x in json.loads(r.stdout)['findings']))
 def test_declared_image_layers_must_decode_to_tar_and_match_diff_ids(self):
  # Hashes/sizes of every substituted blob, manifest and index are recomputed.
  # A separate valid layer still provides the required app entrypoint.
  with tempfile.TemporaryDirectory(prefix='pv-artifact-gate-') as d:
   f=pathlib.Path(d)/'image.tar'
   cases=[image(b'ok',mutate_layer=lambda b:b'XX'+b[2:]),image(b'ok',mutate_layer=lambda b:gzip.compress(b'not a tar')),image(b'ok',bad_diff_id=True)]
   for data in cases:
    f.write_bytes(data);r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('artifact-privacy-scan.py')),'--image-archive',str(f)],capture_output=True,text=True)
    self.assertEqual(r.returncode,2,r.stdout);self.assertFalse(json.loads(r.stdout)['complete'])
 def test_required_app_must_survive_in_the_referenced_image(self):
  with tempfile.TemporaryDirectory(prefix='pv-artifact-gate-') as d:
   f=pathlib.Path(d)/'image.tar'
   for data in [image(b'ok',missing_app=True,orphan_app=True),image(b'ok',delete_app=True)]:
    f.write_bytes(data);r=subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name('artifact-privacy-scan.py')),'--image-archive',str(f)],capture_output=True,text=True)
    self.assertEqual(r.returncode,2,r.stdout);self.assertFalse(json.loads(r.stdout)['complete'])
 def test_tar_padding_and_trailing_metadata_are_scanned(self):
  plain=tar({'module.js':b'ok'})
  for data in [plain+b'PV-CANARY-SECRET',plain[:514]+b'PV-CANARY-SECRET'+plain[530:]]:
   s=p.Scanner();s.archive(gzip.compress(data));self.assertTrue(any(x['family']=='canary' for x in s.findings))
 def test_tar_boundary_split_value_and_valid_opaque_replacement(self):
  data=tar({'module.js':b'PV-CANARY-' });at=512+len(b'PV-CANARY-');data=data[:at]+b'SECRET'+data[at+6:]
  s=p.Scanner();s.archive(data);self.assertTrue(any(x['family']=='canary' for x in s.findings))
  s=p.Scanner();s.archive(image(b'ok',replacement_opaque=True),image_outer=True);self.assertTrue(s.result()['pass'])
 def test_corrupted_compressed_payload_never_clean(self):
  s=p.Scanner()
  with self.assertRaises(Exception):s.payload(b'\x1f\x8bcorrupted','x.gz')
if __name__=='__main__':unittest.main()
