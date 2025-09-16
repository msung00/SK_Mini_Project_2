document.addEventListener('DOMContentLoaded', () => {
    const logInput = document.getElementById('logInput');
    const analyzeButton = document.getElementById('analyzeButton');
    const resultsContainer = document.getElementById('resultsContainer');
    const reportOutput = document.getElementById('reportOutput');
    const loadingAnimation = document.getElementById('loadingAnimation');
    const downloadButton = document.getElementById('downloadButton');
    const csvFileInput = document.getElementById('csvFileInput');

    // 파일 업로드 이벤트 리스너
    csvFileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            logInput.value = e.target.result;
        };
        reader.readAsText(file);
    });

    // '분석 시작' 버튼 클릭 이벤트 (비동기 async 함수로 변경)
    analyzeButton.addEventListener('click', async () => {
        const logData = logInput.value;
        if (!logData.trim()) {
            alert('분석할 로그 데이터를 입력해주세요.');
            return;
        }

        // UI 상태 업데이트
        resultsContainer.classList.remove('hidden');
        reportOutput.innerHTML = '';
        loadingAnimation.style.display = 'block';
        downloadButton.classList.add('hidden');
        document.title = "Analyzing...";

        try {
            // Python Flask 서버의 '/analyze' API에 POST 요청 보내기
            const response = await fetch('http://127.0.0.1:5000/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ log_data: logData }) // 로그 데이터를 JSON 형식으로 전송
            });

            if (!response.ok) {
                // 서버에서 4xx, 5xx 에러 응답 시 예외 발생
                const errorData = await response.json();
                throw new Error(errorData.error || '서버에서 알 수 없는 오류가 발생했습니다.');
            }

            // 서버로부터 받은 AI 분석 결과 (JSON)
            const analysisResult = await response.json();
            
            // 받은 결과를 화면에 타이핑 효과와 함께 표시
            displayReportWithTyping(analysisResult);

            downloadButton.classList.remove('hidden');
            document.title = "Analysis Complete!";

        } catch (error) {
            console.error('API 호출 오류:', error);
            // 에러 발생 시 사용자에게 알림
            reportOutput.innerHTML = `<div class="report"><h2 class="danger">분석 실패</h2><p style="color: #ffcdd2;">AI 서버와 통신하는 데 실패했습니다. 서버가 실행 중인지 확인해주세요. (오류: ${error.message})</p></div>`;
        } finally {
            // 성공/실패 여부와 관계없이 로딩 애니메이션 숨기기
            loadingAnimation.style.display = 'none';
        }
    });

    // PDF 다운로드 버튼 (브라우저 인쇄 기능 사용)
    downloadButton.addEventListener('click', () => {
        window.print();
    });

    // 서버에서 받은 JSON 데이터를 HTML로 변환하여 화면에 표시하는 함수
    function displayReportWithTyping(data) {
        // API 응답 구조에 맞게 화면에 표시할 데이터 객체 생성
        const reportData = {
            level: getLevelClass(data.threat_level),
            icon: getIconForLevel(data.threat_level),
            title: data.detected_anomalies && data.detected_anomalies.length > 0 ? data.detected_anomalies[0].anomaly_type : '분석 완료',
            summary: data.log_summary || '요약 정보가 없습니다.',
            analysis: data.detected_anomalies && data.detected_anomalies.length > 0 ? data.detected_anomalies[0].description : '특이사항이 발견되지 않았습니다.',
            actions: data.remediation_plan ? data.remediation_plan.map(plan => `<b>[${plan.priority}]</b> ${plan.action} (이유: ${plan.reason})`) : []
        };
        
        const reportDiv = document.createElement('div');
        reportDiv.className = 'report';

        reportDiv.innerHTML = `
            <h2 class="${reportData.level}"><i class="ph-bold ${reportData.icon}"></i><span id="reportTitle"></span></h2>
            <div class="summary">
                <h3><i class="ph-bold ph-chart-bar"></i>상황 요약</h3>
                <p id="reportSummary"></p>
            </div>
            <div class="analysis">
                <h3><i class="ph-bold ph-virus"></i>위협 분석</h3>
                <p id="reportAnalysis"></p>
            </div>
            <div class="actions">
                <h3><i class="ph-bold ph-shield-check"></i>권장 대응 방안</h3>
                <ol id="reportActions"></ol>
            </div>
        `;
        reportOutput.appendChild(reportDiv);
        
        // 타이핑 효과 적용
        const typingSpeed = 10;
        typewriter('reportTitle', reportData.title, typingSpeed);
        typewriter('reportSummary', reportData.summary, typingSpeed, 500);
        typewriter('reportAnalysis', reportData.analysis, typingSpeed, 1500);
        
        setTimeout(() => {
            const actionsList = document.getElementById('reportActions');
            reportData.actions.forEach((action, index) => {
                setTimeout(() => {
                    const li = document.createElement('li');
                    actionsList.appendChild(li);
                    typewriter(li, action, typingSpeed, true); // HTML 태그를 해석하도록 설정
                }, index * 800);
            });
        }, 2500);
    }

    // threat_level에 따라 CSS 클래스를 반환하는 함수
    function getLevelClass(level) {
        switch (level ? level.toLowerCase() : '') {
            case '심각':
            case '높음':
                return 'danger';
            case '중간':
                return 'warning';
            default:
                return 'info';
        }
    }

    // threat_level에 따라 아이콘을 반환하는 함수
    function getIconForLevel(level) {
        switch (level ? level.toLowerCase() : '') {
            case '심각':
            case '높음':
                return 'ph-skull';
            case '중간':
                return 'ph-binoculars';
            default:
                return 'ph-check-circle';
        }
    }

    // 타이핑 효과 함수 (HTML 태그를 처리하는 기능 추가)
    function typewriter(target, text, speed, allowHtml = false, delay = 0) {
        setTimeout(() => {
            const targetElement = typeof target === 'string' ? document.getElementById(target) : target;
            const cursor = document.createElement('span');
            cursor.className = 'typing-cursor';
            targetElement.appendChild(cursor);
            
            if (allowHtml) {
                const tempDiv = document.createElement('div');
                tempDiv.innerHTML = text;
                const nodes = Array.from(tempDiv.childNodes);
                let currentNodeIndex = 0;
                let currentTextIndex = 0;

                function typeHtml() {
                    if (currentNodeIndex < nodes.length) {
                        const node = nodes[currentNodeIndex];
                        if (node.nodeType === Node.TEXT_NODE) {
                            if (currentTextIndex < node.textContent.length) {
                                cursor.before(node.textContent[currentTextIndex]);
                                currentTextIndex++;
                                setTimeout(typeHtml, speed);
                            } else {
                                currentNodeIndex++;
                                currentTextIndex = 0;
                                typeHtml();
                            }
                        } else {
                            cursor.before(node.cloneNode(true));
                            currentNodeIndex++;
                            typeHtml();
                        }
                    } else {
                        cursor.remove();
                    }
                }
                typeHtml();

            } else {
                let i = 0;
                function type() {
                    if (i < text.length) {
                        cursor.before(text.charAt(i));
                        i++;
                        setTimeout(type, speed);
                    } else {
                        cursor.remove();
                    }
                }
                type();
            }
        }, delay);
    }
    
    // 별똥별 효과 관련 코드
    const canvas = document.getElementById('shootingStars');
    const ctx = canvas.getContext('2d');
    let stars = [];
    let animationFrameId;

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    class Star {
        constructor() {
            this.reset();
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
        }

        reset() {
            this.x = Math.random() * canvas.width;
            this.y = 0;
            this.size = Math.random() * 2 + 0.5;
            this.speed = Math.random() * 2 + 1;
            this.opacity = Math.random() * 0.7 + 0.3;
            this.tailLength = Math.random() * 50 + 20;
            this.color = `rgba(255, 255, 255, ${this.opacity})`;
            this.angle = Math.PI / 4 + (Math.random() - 0.5) * Math.PI / 8;
        }

        update() {
            this.x += Math.cos(this.angle) * this.speed;
            this.y += Math.sin(this.angle) * this.speed;

            if (this.y > canvas.height || this.x > canvas.width) {
                this.reset();
            }
        }

        draw() {
            ctx.beginPath();
            ctx.lineWidth = this.size;
            ctx.strokeStyle = this.color;
            ctx.lineCap = 'round';
            
            ctx.moveTo(this.x, this.y);
            ctx.lineTo(this.x - Math.cos(this.angle) * this.tailLength, 
                       this.y - Math.sin(this.angle) * this.tailLength);
            ctx.stroke();
        }
    }

    function createStars(count) {
        for (let i = 0; i < count; i++) {
            stars.push(new Star());
        }
    }

    function animateStars() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        stars.forEach(star => {
            star.update();
            star.draw();
        });

        animationFrameId = requestAnimationFrame(animateStars);
    }

    resizeCanvas();
    createStars(50);
    animateStars();

    window.addEventListener('resize', resizeCanvas);

    window.addEventListener('beforeunload', () => {
        cancelAnimationFrame(animationFrameId);
    });
});