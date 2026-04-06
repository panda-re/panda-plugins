import evtxtract

def run(imagename):
    with open(imagename, 'rb') as f:
        buf = f.read()
    offsets = evtxtract.carvers.find_evtx_records(buf)

    records = []
    for offset in offsets:
        record = evtxtract.carvers.extract_record(buf, offset)
        records.append(record)
    
    return records

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Test analysis")
    parser.add_argument("--image_name", default="../volatility/mymem.dd")
    args = parser.parse_args()
    print(run(args.image_name))