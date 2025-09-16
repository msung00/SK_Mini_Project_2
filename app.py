import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from openai import OpenAI
from dotenv import load_dotenv

# .env 파일에서 환경 변수 불러오기
load_dotenv()

# 환경 변수에서 API 키 가져오기
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

# Flask 앱 및 OpenAI 클라이언트 초기화
app = Flask(__name__)
CORS(app)  # <-- 2. 이 줄을 추가하여 CORS를 모든 경로에 허용합니다.
client = OpenAI(api_key=api_key)

# 로그 내용을 보고 타입을 결정하는 간단한 함수
def determine_log_type(log_data):
    log_str = str(log_data).lower()
    if "failed" in log_str and ("password" in log_str or "login" in log_str):
        return "login_failure"
    if "scan" in log_str:
        return "port_scan"
    if "malware" in log_str or "wannacry" in log_str:
        return "malware_detection"
    return "unusual_access"

# 팀원의 프롬프트 생성 함수 (내용은 간소화하여 표시)
def create_gpt_prompt(log_type, raw_log_data):
    # ... (이전 답변의 프롬프트 생성 로직과 동일) ...
    structured_log_json = json.dumps(raw_log_data, indent=4, ensure_ascii=False)
    system_message = (
        "당신은 최고 수준의 AI 보안 분석가입니다. 당신의 목표는 제공된 보안 로그를 "
        "정확하게 분석하고, 위협을 탐지하며, 명확하고 실행 가능한 대응 방안을 제시하는 것입니다. "
        "당신의 모든 응답은 신뢰할 수 있고, 전문적인 톤을 유지해야 합니다."
    )
    prompt_templates = {
        'login_failure': (
            "다음은 사용자 로그인 실패 시도와 관련된 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 사용자 ID, 소스 IP, 시도 시간, 실패 횟수 등을 요약하세요.\n"
            "2. **이상 징후 탐지:** 짧은 시간 내에 반복적으로 발생하는 로그인 실패와 같은 "
            "무차별 대입 공격(Brute-force attack) 패턴을 탐지하고, 의심스러운 IP를 식별하세요.\n"
            "3. **대응 시나리오 제안:** 해당 계정 잠금, IP 차단, 2단계 인증 활성화 등의 "
            "대응 방안을 우선순위에 따라 제시하세요."
        ),
        'port_scan': (
            "다음은 포트 스캔 공격 시도와 관련된 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 공격자 IP, 대상 시스템, 스캔된 포트 범위, 시도 시간을 요약하세요.\n"
            "2. **이상 징후 탐지:** 비정상적으로 넓은 포트 범위를 스캔하거나, 매우 짧은 시간 내에 "
            "다수의 연결 시도가 발생하는 패턴을 탐지하세요.\n"
            "3. **대응 시나리오 제안:** 공격자 IP 차단, 방화벽(Firewall) 규칙 업데이트, "
            "침입 탐지 시스템(IDS) 알림 설정 등의 방안을 제시하세요."
        ),
        'malware_detection': (
            "다음은 악성코드 탐지 시스템에서 발생한 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 탐지된 악성코드의 이름, 감염된 파일 경로, 호스트 시스템, "
            "탐지 시간을 요약하세요.\n"
            "2. **이상 징후 탐지:** 해당 악성코드가 네트워크 내 다른 시스템으로 확산될 가능성, "
            "혹은 추가적인 의심스러운 프로세스를 식별하세요.\n"
            "3. **대응 시나리오 제안:** 감염된 호스트 시스템의 네트워크 격리, 악성코드 제거, "
            "전체 시스템에 대한 추가 정밀 검사 등의 방안을 우선순위에 따라 제시하세요."
        ),
        'unusual_access': (
            "다음은 비정상적인 데이터 접근 시도와 관련된 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 접근 시도한 사용자, 시간, 접근 대상 파일/디렉터리, 시도 결과 등을 요약하세요.\n"
            "2. **이상 징후 탐지:** 특정 사용자가 평소 접근하지 않던 중요한 데이터에 "
            "비정상적인 시간에 접근을 시도하는 패턴을 탐지하세요.\n"
            "3. **대응 시나리오 제안:** 해당 사용자의 접근 권한 일시 정지, "
            "접근 시도에 대한 조사, 관련 관리자에게 알림 등의 방안을 제시하세요."
        )
    }
    user_message = (
        f"**로그 유형:** {log_type}\n\n"
        f"**로그 데이터:**\n"
        f"```json\n{structured_log_json}\n```\n\n"
        f"**단계별 분석 지시:**\n"
        f"{prompt_templates.get(log_type, prompt_templates['unusual_access'])}\n\n"
        "**출력 형식:**\n"
        "결과는 아래의 JSON 형식으로 출력하세요. 각 필드에 대한 설명에 맞춰 내용을 채워주세요.\n"
        "```json\n"
        "{\n"
        "  \"log_summary\": \"로그의 핵심 내용을 간결하게 요약\",\n"
        "  \"detected_anomalies\": [ {\"anomaly_type\": \"탐지된 이상 징후의 유형 (예: Brute-force)\", \"description\": \"이상 징후에 대한 구체적인 설명\"} ],\n"
        "  \"threat_level\": \"'정보', '낮음', '중간', '높음', '심각' 중 하나로 평가하여 가장 적절한 등급을 문자열로 기입\",\n"
        "  \"remediation_plan\": [ {\"priority\": \"'긴급', '높음', '중간', '낮음' 중 하나로 우선순위 설정\", \"action\": \"수행해야 할 구체적인 대응 조치\", \"reason\": \"이 조치를 해당 우선순위로 수행해야 하는 이유를 보안 관점에서 구체적으로 설명\"} ]\n"
        "}\n"
        "```"
    )
    return [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]

# API 엔드포인트
@app.route('/analyze', methods=['POST'])
def analyze_log():
    try:
        log_data = request.json['log_data']
        log_type = determine_log_type(log_data)
        messages = create_gpt_prompt(log_type, {"raw_log": log_data})
        
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=messages,
            response_format={"type": "json_object"}
        )
        analysis_json_string = completion.choices[0].message.content
        return json.loads(analysis_json_string)

    except Exception as e:
        print(f"오류 발생: {e}")
        return jsonify({"error": "분석 중 오류가 발생했습니다."}), 500

# 서버 실행
if __name__ == '__main__':
    app.run(port=5000, debug=True)