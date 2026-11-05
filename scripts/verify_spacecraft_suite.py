"""Run the eight-project acceptance corpus and require exact defect evidence."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from prepare_spacecraft_suite import prepare

def verify(output,compiler='gcc',constraints=False):
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True)
    prepare(compiler)
    manifest=json.loads((ROOT/'examples/spacecraft_suite/manifest.json').read_text(encoding='utf-8'))
    records=[];defects=[]
    detector={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'ecdet').rglob('*.py')}
    for project in manifest['projects']:
        root=ROOT/project['path'];dest=output/project['name']
        dest.mkdir(exist_ok=True)
        if (dest/'receipt.json').exists():raise ValueError('Refusing to overwrite completed receipt')
        before={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in project['source_sha256']}
        assert all(hashlib.sha256((root/n).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==h for n,h in project['normalized_source_sha256'].items()),'Fixture differs from reviewed manifest'
        command=[sys.executable,'-m','ecdet','scan',str(root),'--no-build','--profile','industrial','-o',str(dest)]
        contract=ROOT/'examples/business_contracts/contracts'/project['name']/'contracts.json'
        if contract.exists():command+=['--contracts',str(contract),'--contract-compiler',compiler]
        if constraints:command+=['--constraints']
        start=time.monotonic()
        with (dest/'scan.log').open('w',encoding='utf-8') as log:
            run=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        sarif=json.loads((dest/'results.sarif').read_text(encoding='utf-8'))
        alerts=sarif['runs'][0]['results'];native=json.loads((dest/'codechecker/latest.json').read_text(encoding='utf-8'))
        assert native['status']=='complete',native['status']
        assert all(hashlib.sha256((root/n).read_bytes()).hexdigest()==h for n,h in before.items())
        for case in [d for d in manifest['defects'] if d['project']==project['name']]:
            matched=[]
            for a in alerts:
                loc=a['locations'][0]['physicalLocation'];props=a.get('properties',{})
                same=loc['artifactLocation']['uri']==case['file'] and a['ruleId']==case['rule']
                exact=(props.get('analysis',{}).get('contract_id')==case['contract_id'] if case['category']=='business' else loc['region']['startLine']==case['line'])
                expected_engine=case['required_engine']
                engine_matches=(props.get('engine','').startswith('builtin') if expected_engine=='builtin' else props.get('engine')==('business-contract' if expected_engine=='contract' else expected_engine))
                if same and exact and engine_matches:matched.append(dict(rule=a['ruleId'],engine=props.get('engine'),line=loc['region']['startLine']))
            defects.append(dict(case,detected=bool(matched),evidence=matched))
        for exclusion in [d for d in manifest['excluded_expectations'] if d['project']==project['name']]:
            assert not any(a['ruleId']==exclusion['rule'] for a in alerts),exclusion
        receipt=dict(project=project['name'],command=command,returncode=run.returncode,seconds=round(time.monotonic()-start,3),source_sha256=before,raw_alerts=len(alerts),analyzers=native.get('analyzers'),ctu=native.get('ctu'),codechecker='complete')
        assert run.returncode in (0,1,2),run.returncode
        receipt['subanalyses']={}
        for kind,relative in [('z3','constraints.json'),('business','business-contracts/contracts.json'),('esbmc','esbmc/receipt.json')]:
            path=dest/relative
            if path.exists():
                value=json.loads(path.read_text(encoding='utf-8'))
                receipt['subanalyses'][kind]=value.get('status_counts') or value.get('status') or 'see receipt'
        (dest/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
        records.append(receipt);print(project['name'],run.returncode,len(alerts),flush=True)
    assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in detector.items()),'Detector changed during suite'
    summary=dict(acceptance_scope='44 registered root detections and excluded false-positive assertions; subanalysis completeness is separate',projects=records,defects=defects,detected=sum(d['detected'] for d in defects),total=len(defects),detector_sha256=detector)
    (output/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    assert summary['detected']==44 and summary['total']==44,[d for d in defects if not d['detected']]
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--compiler',default='gcc');parser.add_argument('--constraints',action='store_true');args=parser.parse_args()
    result=verify(args.output,args.compiler,args.constraints);print('DEFECT_ROOTS',result['detected'],'/',result['total'])
