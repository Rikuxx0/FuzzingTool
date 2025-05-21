import json
import os
from datetime import datetime


# ファジングした結果をJSONファイルに保存するための関数
class FuzzLogger:
    def __init__(self, filename= "output/fuzz_results.json", overwrite=True):
        self.filename = filename
        self.results = []
        self.overwrite = overwrite

        # ディレクトリ作成（なければ作る）
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        if not overwrite and os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                try:
                    self.results = json.load(f)
                except json.JSONDecodeError:
                    self.results = []

    #attack_typeも実装予定
    def log_result(self, target_url, payload, response_code, response_body, injection_type ,injection_detected, fuzzing_results=None, error_contents=None):
        result = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "payload": payload,
            "response_code": response_code,
            "response_body": response_body,
            "injection_type": injection_type,
            "injection_detected": injection_detected,
            "fuzzing_results": fuzzing_results,
            "error_contents": error_contents,
        }
        self.results.append(result)

    def save(self):
        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)