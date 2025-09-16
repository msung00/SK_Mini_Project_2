import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY 환경 변수가 설정되지 않았습니다.")

app = Flask(__name__)
CORS(app)
client = OpenAI(api_key=api_key)

def create_unified_prompt(raw_log_data):
    """
    모든 로그 유형을 분석할 수 있는 통합 프롬프트를 생성합니다.
    """
    log_json_string = json.dumps({"raw_log": raw_log_data}, indent=4, ensure_ascii=False)
    
    system_message = (
        "당신은 최고 수준의 AI 보안 분석가입니다. 당신의 목표는 제공된 보안 로그 묶음에서 "
        "발생할 수 있는 **모든 종류의 이상 징후와 공격 패턴을 탐지**하고, "
        "명확하고 실행 가능한 대응 방안을 제시하는 것입니다."
    )
    
    user_message = (
        f"다음 보안 로그 데이터를 종합적으로 분석하세요. 로그에는 Brute Force, Port Scan, DoS, Web Attack 등 "
        f"다양한 유형의 공격이 포함될 수 있습니다. 모든 잠재적 위협을 식별하고 아래 지시에 따라 응답하세요.\n\n"
        f"**분석 대상 로그:**\n"
        f"```json\n{log_json_string}\n```\n\n"
        "**수행 작업:**\n"
        "1. **로그 요약:** 전체 로그에서 발생한 주요 이벤트들을 간결하게 요약하세요.\n"
        "2. **이상 징후 탐지:** 로그에 나타난 **모든** 의심스러운 활동 및 공격 패턴을 찾아 목록으로 만드세요. 각 항목에는 공격 유형과 구체적인 근거를 포함해야 합니다.\n"
        "3. **종합 위협 수준 평가:** 탐지된 모든 위협을 고려하여 전체적인 위협 수준을 평가하세요.\n"
        "4. **대응 시나리오 제안:** 각 위협에 대한 대응 방안을 우선순위에 따라 목록으로 제시하세요.\n\n"
        "**출력 형식:**\n"
        "결과는 반드시 아래의 JSON 형식으로만 출력하세요.\n"
        "```json\n"
        "{\n"
        "  \"log_summary\": \"전체 로그에 대한 종합적인 요약\",\n"
        "  \"detected_anomalies\": [\n"
        "    {\"anomaly_type\": \"탐지된 첫 번째 이상 징후 유형 (예: Brute-force)\", \"description\": \"첫 번째 이상 징후에 대한 구체적인 설명과 근거\"},\n"
        "    {\"anomaly_type\": \"탐지된 두 번째 이상 징후 유형 (예: Web Attack - XSS)\", \"description\": \"두 번째 이상 징후에 대한 구체적인 설명과 근거\"}\n"
        "  ],\n"
        "  \"threat_level\": \"'정보', '낮음', '중간', '높음', '심각' 중 하나로 종합 평가\",\n"
        "  \"remediation_plan\": [\n"
        "    {\"priority\": \"'긴급', '높음', '중간', '낮음'\", \"action\": \"수행해야 할 구체적인 대응 조치\", \"reason\": \"이 조치를 수행해야 하는 이유\"}\n"
        "  ]\n"
        "}\n"
        "```"
    )

    return [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]

@app.route('/analyze', methods=['POST'])
def analyze_log():
    try:
        log_data = request.json['log_data']
        messages = create_unified_prompt(log_data)
        
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

if __name__ == '__main__':
    app.run(port=5000, debug=True)