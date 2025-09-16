# 🤖 AI Security Analyst

> **생성형 AI 기반 보안 로그 자동 분석 도구** > Splunk 로그, CSV, 텍스트 파일을 업로드하여  
> AI 기반의 **자동화된 보안 분석 리포트**를 받아보세요.

---

<p align="center">
  <img src="https://user-images.githubusercontent.com/username/repo/assets/demo.gif" width="750">
  <br>
  <em><img width="1752" height="867" alt="image" src="https://github.com/user-attachments/assets/38f76414-99ff-49bb-8621-0b629820aa5b" />
</em>
</p>

## 🚀 주요 기능

### 📈 AI 기반 자동 분석
- **1단계: 로그 입력 및 유형 식별** → 텍스트 붙여넣기 또는 `.csv`, `.log` 파일 업로드
- **2단계: OpenAI API 연동 분석** → `gpt-4-turbo` 모델을 통해 다중 공격 패턴 동시 분석
- **3단계: 동적 리포트 생성** → 분석 결과를 바탕으로 아래 내용들을 실시간으로 생성

### 📄 분석 리포트 상세 내용
- **로그 요약**: AI가 전체 로그의 핵심 내용을 자연어로 요약
- **위협 탐지**: `Brute Force`, `Port Scan`, `Web Attack(XSS, SQL Injection)` 등 탐지된 모든 위협 목록화
- **대응 방안 제시**: 탐지된 위협에 대한 우선순위, 구체적인 조치, 그리고 이유를 포함한 실행 계획 제공
- **PDF 보고서 생성**: 브라우저의 인쇄 기능을 통해 분석 결과 보고서 저장 지원

### ✨ 사용자 경험(UX)
- **동적 시각 효과**: 별똥별이 떨어지는 배경, 글래스모피즘 UI 적용
- **인터랙티브 애니메이션**: AI가 실시간으로 답변하는 듯한 타이핑 효과로 몰입감 증대

---

## 🛠️ 기술 스택

<p align="center">
  <strong>Frontend:</strong><br>
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white"/>
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white"/>
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black"/>
</p>
<p align="center">
  <strong>Backend:</strong><br>
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white"/>
</p>

---

## ⚙️ 설치 및 실행 방법

1.  **프로젝트 클론**
    ```bash
    git clone [https://github.com/your-username/AI-Security-Analyst.git](https://github.com/your-username/AI-Security-Analyst.git)
    cd AI-Security-Analyst
    ```

2.  **백엔드 설정**
    -   가상 환경 생성 및 활성화
        ```bash
        python -m venv venv
        source venv/bin/activate  # macOS/Linux
        # venv\Scripts\activate  # Windows
        ```
    -   필요한 라이브러리 설치
        ```bash
        pip install Flask openai python-dotenv flask-cors
        ```
    -   `.env` 파일 생성 후 API 키 입력
        ```env
        OPENAI_API_KEY="YOUR_API_KEY"
        ```

3.  **서버 실행**
    ```bash
    python app.py
    ```

4.  **프론트엔드 실행**
    -   웹 브라우저에서 `Interface.html` 파일을 엽니다.

---

## 📂 프로젝트 구조

```bash
📦 AI-Security-Analyst/
├── 📜 app.py              # Flask 백엔드 서버
├── 📜 Interface.html       # 메인 UI 페이지
├── 📜 script.js           # 프론트엔드 로직 (API 호출, 동적 효과)
├── 📜 style.css           # UI 스타일시트
├── 📜 .env                # OpenAI API 키 저장 파일
└── 📜 README.md           # 프로젝트 소개 파일
```
