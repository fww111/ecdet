"""Real-tool positive/fixed acceptance; no fake fallback."""
from pathlib import Path
import argparse
import json
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from ecdet.l2_ir.sarif import build_sarif
from ecdet.l3_analysis.dynamic.libfuzzer import LibFuzzerEngine, LIBFUZZER_RULE, generate_byte_harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    seed = output/'initial_seed'
    seed.write_bytes(bytes([0xa5, 0]))
    example = REPO/'examples/libfuzzer_demo'
    assert (example/'harness.c').read_text(encoding='utf-8') == generate_byte_harness('parse_packet')
    engine = LibFuzzerEngine(clang=args.clang, runs=5000, timeout=20, max_len=64)
    records = {}
    for label, source in [('bad', 'packet_bad.c'), ('fixed', 'packet_fixed.c')]:
        result = engine.run(example, Path('harness.c'), output/label, sources=[Path(source)], corpus=[seed])
        records[label] = result.to_dict()
        (output/label/'results.sarif').write_text(json.dumps(build_sarif(result.alerts, [LIBFUZZER_RULE]),
                                                              ensure_ascii=False, indent=2), encoding='utf-8')
    records['accepted'] = (records['bad']['status']=='FINDING' and
                           records['fixed']['status']=='COMPLETED' and
                           len(records['bad']['alerts'])>0 and not records['fixed']['alerts'])
    (output/'validation.json').write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'accepted':records['accepted'],
                      **{k:{'status':records[k]['status'], 'alerts':len(records[k]['alerts']),
                            'coverage':records[k]['metadata'].get('coverage')}
                         for k in ['bad','fixed']}},ensure_ascii=False))
    return 0 if records['accepted'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
