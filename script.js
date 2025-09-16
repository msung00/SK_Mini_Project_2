document.addEventListener('DOMContentLoaded', () => {
    const logInput = document.getElementById('logInput');
    const analyzeButton = document.getElementById('analyzeButton');
    const resultsContainer = document.getElementById('resultsContainer');
    const reportOutput = document.getElementById('reportOutput');
    const loadingAnimation = document.getElementById('loadingAnimation');
    const downloadButton = document.getElementById('downloadButton');

    analyzeButton.addEventListener('click', () => {
        const logData = logInput.value;
        if (!logData.trim()) {
            alert('분석할 로그 데이터를 입력해주세요.');
            return;
        }

        resultsContainer.classList.remove('hidden');
        reportOutput.innerHTML = '';
        loadingAnimation.style.display = 'block';
        downloadButton.classList.add('hidden');
        document.title = "Analyzing...";

        setTimeout(() => {
            loadingAnimation.style.display = 'none';
            const reportData = generateMockReport(logData);
            
            displayReportWithTyping(reportData);

            downloadButton.classList.remove('hidden');
            document.title = "Analysis Complete!";
        }, 2500);
    });

    downloadButton.addEventListener('click', () => {
        window.print();
    });

    function displayReportWithTyping(data) {
        const reportDiv = document.createElement('div');
        reportDiv.className = 'report';

        reportDiv.innerHTML = `
            <h2 class="${data.level}"><i class="ph-bold ${data.icon}"></i><span id="reportTitle"></span></h2>
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
        
        const typingSpeed = 20;
        typewriter('reportTitle', data.title, typingSpeed);
        typewriter('reportSummary', data.summary, typingSpeed, 500);
        typewriter('reportAnalysis', data.analysis, typingSpeed, 1500);
        
        setTimeout(() => {
            const actionsList = document.getElementById('reportActions');
            data.actions.forEach((action, index) => {
                setTimeout(() => {
                    const li = document.createElement('li');
                    actionsList.appendChild(li);
                    typewriter(li, action, typingSpeed);
                }, index * 500);
            });
        }, 2500);
    }

    function typewriter(target, text, speed, delay = 0) {
        setTimeout(() => {
            let i = 0;
            const targetElement = typeof target === 'string' ? document.getElementById(target) : target;
            
            const cursor = document.createElement('span');
            cursor.className = 'typing-cursor';
            targetElement.appendChild(cursor);

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
        }, delay);
    }

    function generateMockReport(log) {
        const lowerCaseLog = log.toLowerCase();
        if (lowerCaseLog.includes('failed') && lowerCaseLog.includes('login')) {
            return { level: 'danger', icon: 'ph-skull', title: '무차별 대입 공격 (Brute Force) 의심', summary: '특정 IP 주소에서 관리자 계정에 대해 짧은 시간 동안 다수의 로그인 실패가 감지되었습니다.', analysis: '자동화된 도구를 사용하여 비밀번호를 알아내려는 공격의 전형적인 패턴입니다. 성공 시 시스템 접근 권한이 탈취될 수 있습니다.', actions: ['방화벽에서 공격 근원지 IP를 즉시 차단하십시오.', '공격 대상이 된 계정을 일시적으로 잠금 처리하여 추가 공격을 방지하십시오.', '계정 잠금 정책 활성화 여부 및 임계값을 검토하십시오.'] };
        } else if (lowerCaseLog.includes('scan') || lowerCaseLog.includes('nmap')) {
            return { level: 'warning', icon: 'ph-binoculars', title: '포트 스캔 (Port Scan) 활동 탐지', summary: '하나의 IP 주소에서 단일 호스트의 여러 포트로 순차적인 접근이 탐지되었습니다.', analysis: '시스템의 활성화된 서비스와 잠재적 취약점을 파악하려는 정찰 활동의 초기 단계일 가능성이 높습니다.', actions: ['해당 IP의 과거 활동 로그를 검토하여 다른 의심스러운 행적을 확인하십시오.', '불필요하게 외부에 노출된 포트가 있는지 방화벽 설정을 재검토하십시오.', 'IDS에서 해당 IP를 예의주시하도록 정책을 추가하십시오.'] };
        } else {
            return { level: 'info', icon: 'ph-check-circle', title: '분석 완료: 특이사항 없음', summary: '입력된 로그 데이터에 대한 분석이 완료되었습니다.', analysis: '탐지된 로그에서 즉각적인 조치가 필요한 심각한 위협 패턴은 발견되지 않았습니다. 지속적인 모니터링이 권장됩니다.', actions: ['주기적으로 시스템 로그를 검토하여 비정상적인 활동이 없는지 확인하십시오.', '최신 보안 패치를 적용하여 시스템을 안전하게 유지하십시오.', '중요 시스템에 대한 접근 제어 정책을 정기적으로 검토하십시오.'] };
        }
    }

    // ▼▼▼ 별똥별 효과를 위한 JavaScript 코드 ▼▼▼
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
            this.x = Math.random() * canvas.width; // 초기 x 위치를 무작위로 설정
            this.y = Math.random() * canvas.height; // 초기 y 위치를 무작위로 설정
        }

        reset() {
            this.x = Math.random() * canvas.width;
            this.y = 0; // 항상 위에서 시작
            this.size = Math.random() * 2 + 0.5;
            this.speed = Math.random() * 2 + 1; // 1 ~ 3
            this.opacity = Math.random() * 0.7 + 0.3; // 0.3 ~ 1
            this.tailLength = Math.random() * 50 + 20; // 꼬리 길이
            this.color = `rgba(255, 255, 255, ${this.opacity})`;
            this.angle = Math.PI / 4 + (Math.random() - 0.5) * Math.PI / 8; // 대략 45도 방향
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
            // 꼬리 그리기 (반대 방향으로)
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
        ctx.clearRect(0, 0, canvas.width, canvas.height); // 프레임 지우기
        
        stars.forEach(star => {
            star.update();
            star.draw();
        });

        animationFrameId = requestAnimationFrame(animateStars);
    }

    // 초기화 및 이벤트 리스너
    resizeCanvas();
    createStars(50); // 화면에 50개의 별똥별이 떨어지도록 설정
    animateStars();

    window.addEventListener('resize', resizeCanvas);

    // 페이지에서 나갈 때 애니메이션 중지 (성능 최적화)
    window.addEventListener('beforeunload', () => {
        cancelAnimationFrame(animationFrameId);
    });
    // ▲▲▲ 여기까지 추가합니다 ▲▲▲
});