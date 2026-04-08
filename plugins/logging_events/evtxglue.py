import evtxtract, json, traceback
from collections import defaultdict

def run(imagename):
    with open(imagename, 'rb') as f:
        buf = f.read()
    offsets = evtxtract.carvers.find_evtx_records(buf)

    analysis_results = defaultdict(list)
    for offset in offsets:
        try:
            record = evtxtract.carvers.extract_record(buf, offset)
            analysis_results[record.substitutions[14][1]].append(str(record))
            records.append(record)
        except Exception:
            continue
    
    json_str = json.dumps(analysis_results, indent=1)
    return json_str

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test analysis")
    parser.add_argument("--image_name", default="../volatility/mymem.dd")
    args = parser.parse_args()
    print(run(args.image_name))
