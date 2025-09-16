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

def create_gpt_prompt(log_type, raw_log_data):
    import json
    structured_log_json = json.dumps(raw_log_data, indent=4, ensure_ascii=False)
    system_message = (
        "당신은 최고 수준의 AI 보안 분석가입니다. 당신의 목표는 제공된 보안 로그를 "
        "정확하게 분석하고, 위협을 탐지하며, 명확하고 실행 가능한 대응 방안을 제시하는 것입니다. "
        "당신의 모든 응답은 신뢰할 수 있고, 전문적인 톤을 유지해야 합니다. "
        "각 판단과 대응 조치에는 반드시 이유와 근거를 포함하세요. "
        "추가로, 각 판단에 대해 간단히 한 줄 정도 근거를 덧붙이도록 하세요."
    )
    
    prompt_templates = {
        'login_failure': (
            "다음은 사용자 로그인 실패 시도와 관련된 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 사용자 ID, 소스 IP, 시도 시간, 실패 횟수 등을 요약하세요.\n"
            "2. **이상 징후 탐지:** 짧은 시간 내 반복적인 로그인 실패와 같은 "
            "무차별 대입 공격(Brute-force attack) 패턴을 탐지하고, 의심스러운 IP를 식별하세요.\n"
            "3. **대응 시나리오 제안:** 계정 잠금, IP 차단, 2단계 인증 활성화 등 대응 방안을 우선순위와 함께 제시하세요.\n"
            "4. **분석 근거 표시:** 각 탐지 항목과 대응 조치에는 반드시 근거를 명확하게 설명하세요. "
            "5. 각 판단에 대해 간단히 한 줄 근거를 추가하세요."
        ),
        'port_scan': (
            "다음은 포트 스캔 공격 시도와 관련된 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 공격자 IP, 대상 시스템, 스캔된 포트 범위, 시도 시간을 요약하세요.\n"
            "2. **이상 징후 탐지:** 비정상적으로 넓은 포트 범위 스캔, 짧은 시간 내 다수 연결 시도 패턴 탐지\n"
            "3. **대응 시나리오 제안:** IP 차단, 방화벽 규칙 업데이트, IDS 알림 설정 등 구체적 방안 제시\n"
            "4. **분석 근거 표시:** 각 탐지 항목과 대응 조치에는 반드시 근거와 위험도를 포함하세요. "
            "5. 각 판단에 대해 간단히 한 줄 근거를 추가하세요."
        ),
        'malware_detection': (
            "다음은 악성코드 탐지 시스템에서 발생한 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 탐지된 악성코드 이름, 감염 파일 경로, 호스트 시스템, 탐지 시간 요약\n"
            "2. **이상 징후 탐지:** 해당 악성코드 확산 가능성, 추가 의심 프로세스 식별\n"
            "3. **대응 시나리오 제안:** 감염 호스트 격리, 악성코드 제거, 전체 시스템 추가 검사\n"
            "4. **분석 근거 표시:** 대응 조치별 위험 근거와 우선순위 이유 명확히 설명. "
            "5. 각 판단에 대해 간단히 한 줄 근거를 추가하세요."
        ),
        'unusual_access': (
            "다음은 비정상적인 데이터 접근 시도 로그입니다. 이 로그를 분석하여 "
            "다음 작업을 수행하세요:\n"
            "1. **로그 요약:** 접근 시도 사용자, 시간, 대상 파일/디렉터리, 결과 요약\n"
            "2. **이상 징후 탐지:** 특정 사용자가 평소 접근하지 않던 중요 데이터에 비정상적 시간 접근 패턴 탐지\n"
            "3. **대응 시나리오 제안:** 접근 권한 일시 정지, 조사, 관리자 알림 등 구체적 방안 제시\n"
            "4. **분석 근거 표시:** 이상 징후 판단 근거와 조치 우선순위 이유 포함. "
            "5. 각 판단에 대해 간단히 한 줄 근거를 추가하세요."
        )
    }
    
    user_message = (
        f"**로그 유형:** {log_type}\n\n"
        f"**로그 데이터:**\n"
        f"```json\n{structured_log_json}\n```\n\n"
        f"**단계별 분석 지시:**\n"
        f"{prompt_templates.get(log_type, prompt_templates['unusual_access'])}\n\n"
        "**출력 형식:**\n"
        "결과는 아래 JSON 형식으로 출력하세요. 각 필드에 설명된 내용을 반드시 포함하고, 추가 메타 정보도 제공하세요. "
        "각 판단과 조치에 대해 간단히 한 줄 근거를 덧붙이세요.\n"
        "```json\n"
        "{\n"
        "  \"log_summary\": \"로그의 핵심 내용을 간결하게 요약\",\n"
        "  \"detected_anomalies\": [\n"
        "      {\"anomaly_type\": \"탐지된 이상 징후 유형 (예: Brute-force)\",\n"
        "       \"description\": \"이상 징후에 대한 구체적 설명\",\n"
        "       \"confidence_score\": \"탐지 신뢰도 0~1 범위로 표현\",\n"
        "       \"reason\": \"간단한 한 줄 근거\"\n"
        "      }\n"
        "  ],\n"
        "  \"threat_level\": \"정보, 낮음, 중간, 높음, 심각 중 하나\",\n"
        "  \"remediation_plan\": [\n"
        "      {\"priority\": \"긴급, 높음, 중간, 낮음\",\n"
        "       \"action\": \"구체적 대응 조치\",\n"
        "       \"reason\": \"간단한 한 줄 근거\"\n"
        "      }\n"
        "  ],\n"
        "  \"meta_info\": {\n"
        "       \"analyzed_by_model_version\": \"모델 버전 표시\",\n"
        "       \"analysis_timestamp\": \"분석 수행 시각\",\n"
        "       \"log_data_trust_level\": \"원본 로그 신뢰도 0~1\"\n"
        "  }\n"
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