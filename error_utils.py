import re

def show_error_contents(response_result: str) -> None:
    #エラーメッセージの抽出
    pattern = r"(error\s*[:=].{0,100}|exception\s*[:=].{0,100}|traceback.{0,200})"
    matches = re.findall(pattern, response_result, re.IGNORECASE)
    return [m.strip() for m in matches]