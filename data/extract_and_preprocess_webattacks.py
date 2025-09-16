# extract_and_preprocess_webattacks.py
import pandas as pd
import numpy as np
from pathlib import Path
import json
import argparse

# ---------- 공통 유틸 ----------
def norm_label(s: str) -> str:
    """라벨 문자열 정규화: 어색한 문자(�) → '-' 치환, 소문자 비교 친화"""
    if s is None:
        return ""
    t = str(s).replace("�", "-").replace("–", "-").strip()
    # 공백 정리
    t = " ".join(t.split())
    return t

def pick_labels(label_counts):
    """Web Attack 3종 + BENIGN 선별. 없으면 상위 비-BENIGN 3개."""
    labels = list(label_counts.keys())
    # 정규화 맵
    norm_map = {lbl: norm_label(lbl).lower() for lbl in labels}

    benign = next((lbl for lbl in labels if norm_map[lbl] == "benign"), None)
    web_like = [lbl for lbl in labels if "web attack" in norm_map[lbl]]
    # web-like 없을 경우를 대비해 top-3 non-benign
    non_benign = [lbl for lbl in labels if lbl != benign]
    top_non_benign = sorted(non_benign, key=lambda x: label_counts[x], reverse=True)[:3]

    # Web Attack 안에서 Brute Force/XSS/Sql Injection 우선 정렬
    def web_rank(lbl):
        s = norm_map[lbl]
        if "sql" in s: return 0
        if "brute" in s: return 1
        if "xss" in s: return 2
        return 3
    if web_like:
        chosen = sorted(web_like, key=web_rank)[:3]
    else:
        chosen = top_non_benign

    if benign:
        chosen = chosen + [benign]
    return chosen

# ---------- 1단계: 원본 → 균형 소형셋 ----------
def make_balanced_subset(in_csv: Path, out_dir: Path, sample_per_label: int = 3000, seed: int = 42):
    np.random.seed(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    label_counts = {}
    reservoir = {}  # label -> list of rows (dict)
    chunksize = 100_000
    first_cols = None

    def reservoir_add(label, row_dict):
        buf = reservoir.setdefault(label, [])
        if len(buf) < sample_per_label:
            buf.append(row_dict)
        else:
            # 라벨별 reservoir sampling
            n = label_counts[label]  # 누적 개수
            j = np.random.randint(0, n)  # [0, n-1]
            if j < sample_per_label:
                buf[j] = row_dict

    reader = pd.read_csv(in_csv, chunksize=chunksize, low_memory=False)
    total = 0
    label_col_name = None

    for chunk in reader:
        # 컬럼명 트림
        chunk.rename(columns=lambda c: str(c).strip(), inplace=True)
        if first_cols is None:
            first_cols = list(chunk.columns)
        total += len(chunk)

        # 라벨 컬럼 찾기
        if label_col_name is None:
            for c in chunk.columns:
                if str(c).strip().lower() == "label":
                    label_col_name = c
                    break
            if label_col_name is None:
                raise RuntimeError(f"'Label' 컬럼을 찾지 못함. 예시 컬럼: {chunk.columns[:10].tolist()}")

        # 집계
        vc = chunk[label_col_name].value_counts(dropna=False)
        for k, v in vc.items():
            label_counts[k] = label_counts.get(k, 0) + int(v)

    # 선택 라벨 확정
    chosen_labels = pick_labels(label_counts)

    # 2차 패스: reservoir 채우기
    reader = pd.read_csv(in_csv, chunksize=chunksize, low_memory=False)
    for chunk in reader:
        chunk.rename(columns=lambda c: str(c).strip(), inplace=True)
        for _, row in chunk.iterrows():
            lbl = row[label_col_name]
            if lbl in chosen_labels:
                # 공격 라벨은 전량 유지되도록 sample_per_label를 넉넉히 주거나,
                # BENIGN만 cap 하려면 아래처럼 라벨별 cap 조정 가능
                row_dict = row.to_dict()
                # BENIGN만 cap, 공격 라벨은 거의 전량 유지하고 싶다면:
                # if norm_label(lbl).lower() == "benign":
                #     reservoir_add(lbl, row_dict)
                # else:
                #     reservoir.setdefault(lbl, []).append(row_dict)
                reservoir_add(lbl, row_dict)

    # 결과 저장
    label_counts_sorted = dict(sorted(label_counts.items(), key=lambda x: x[1], reverse=True))
    with open(out_dir / "label_counts.json", "w", encoding="utf-8") as f:
        json.dump(label_counts_sorted, f, ensure_ascii=False, indent=2)

    # 최종 레코드 구성
    mini_records = []
    for lbl in chosen_labels:
        mini_records.extend(reservoir.get(lbl, []))

    mini_df = pd.DataFrame(mini_records)
    raw_out = out_dir / "subset_web_raw_balanced.csv"
    mini_df.to_csv(raw_out, index=False)
    return raw_out, chosen_labels, label_counts_sorted

# ---------- 2단계: 균형셋 → 전처리/정규화 ----------
def preprocess_to_common_schema(in_csv: Path, out_csv: Path):
    df = pd.read_csv(in_csv, low_memory=False)
    cols = set(df.columns)

    def get(*names):
        for n in names:
            if n in cols:
                return df[n]
        return None

    out = pd.DataFrame()
    out["timestamp"] = get("Timestamp")

    out["src_ip"]   = get("Source IP", "Src IP", "src_ip")
    out["src_port"] = get("Source Port", "Src Port", "src_port")
    out["dst_ip"]   = get("Destination IP", "Dst IP", "dst_ip")
    out["dst_port"] = get("Destination Port", "Dst Port", "dst_port")
    out["protocol"] = get("Protocol", "protocol")

    fwd_pkts = get("Tot Fwd Pkts"); bwd_pkts = get("Tot Bwd Pkts")
    if fwd_pkts is not None and bwd_pkts is not None:
        out["pkts_total"] = pd.to_numeric(fwd_pkts, errors="coerce").fillna(0) + \
                            pd.to_numeric(bwd_pkts, errors="coerce").fillna(0)
    fwd_bytes = get("TotLen Fwd Pkts"); bwd_bytes = get("TotLen Bwd Pkts")
    if fwd_bytes is not None and bwd_bytes is not None:
        out["bytes_total"] = pd.to_numeric(fwd_bytes, errors="coerce").fillna(0) + \
                             pd.to_numeric(bwd_bytes, errors="coerce").fillna(0)

    if "Flow Duration" in cols:
        out["flow_duration_ms"] = pd.to_numeric(df["Flow Duration"], errors="coerce")

    out["label"] = get("Label", "label")

    def to_event_type(lbl):
        s = norm_label(lbl).lower()
        if "web attack" in s and "brute" in s: return "web_bruteforce"
        if "web attack" in s and "xss" in s:   return "web_xss"
        if "web attack" in s and "sql" in s:   return "web_sql_injection"
        if "benign" in s:                      return "benign"
        return "attack_other"

    out["event_type"] = out["label"].map(to_event_type)
    out.to_csv(out_csv, index=False)
    return out

# ---------- CLI ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_csv", required=True,
                    help="원본 CSV 경로 (예: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv)")
    ap.add_argument("--outdir", default="cicids_subset_web",
                    help="출력 디렉터리")
    ap.add_argument("--perlabel", type=int, default=3000,
                    help="라벨별 최대 샘플 수 (BENIGN 축소에 유효)")
    args = ap.parse_args()

    in_csv = Path(args.in_csv)
    out_dir = Path(args.outdir)

    raw_out, chosen, counts = make_balanced_subset(in_csv, out_dir, sample_per_label=args.perlabel)
    print(f"[1/2] Balanced subset saved: {raw_out}")
    print(f"Chosen labels: {chosen}")
    print(f"Label counts(top): {list(counts.items())[:10]}")

    pre_out = out_dir / "subset_web_preprocessed.csv"
    df_pre = preprocess_to_common_schema(raw_out, pre_out)
    print(f"[2/2] Preprocessed CSV saved: {pre_out}")
    print(df_pre.head(5))
