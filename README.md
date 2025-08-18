netguard-ids/
├── agent/                                # Thu thập dữ liệu mạng
│   ├── packet_capture.py                  # Class PacketCapture: Bắt gói tin thô từ NIC
│   ├── flow_generator.py                  # Class FlowGenerator: Biến gói tin thành luồng (flows) theo 5-tuple
│   ├── agent_manager.py                   # Class AgentManager: Quản lý vòng đời, config và chạy agent
│   ├── capabilities_setup.sh              # Script gán quyền (setcap) cho phép capture không cần root
│   └── Dockerfile.agent                   # Dockerfile cho service agent
│
├── preprocessor/                          # Xử lý dữ liệu trước khi phát hiện
│   ├── feature_extractor.py               # Class FeatureExtractor: Trích xuất đặc trưng từ flows
│   ├── data_normalizer.py                 # Class DataNormalizer: Chuẩn hóa dữ liệu (scale, encode…)
│   └── preprocessor.py                    # Class Preprocessor: Orchestrator gọi extractor + normalizer
│
├── detector/                              # Phát hiện xâm nhập
│   ├── rule_engine.py                     # Class RuleEngine: So khớp luồng với luật (YAML rules)
│   ├── anomaly_detector.py                # Class AnomalyDetector: ML/DL model dự đoán bất thường
│   ├── model_manager.py                   # Class ModelManager: Load, lưu, update mô hình ML
│   ├── orchestrator.py                    # Class DetectorOrchestrator: Điều phối rule + ML để đưa ra kết luận
│   ├── training/
│   │   └── model_trainer.py               # Class ModelTrainer: Huấn luyện mô hình từ datasets
│   └── rules/
│       └── default_rules.yaml             # Bộ luật mặc định (rule-based detection)
│
├── responder/                             # Phản ứng sau phát hiện
│   ├── alert_handler.py                   # Class AlertHandler: Gửi cảnh báo (Slack, Email, Dashboard)
│   ├── interfaces.py                      # BlockerInterface: interface chuẩn cho các bộ chặn
│   ├── iptables_blocker.py                # Class IptablesBlocker: Chặn IP bằng iptables
│   ├── responder.py                       # Class Responder: Orchestrator, quyết định phản ứng nào cần thực hiện
│   └── README_BLOCKING.md                 # Tài liệu về blocking an toàn
│
├── dashboard/                             # MVC: giao diện quản lý
│   ├── controllers/                       # Controller
│   │   ├── auth_controller.py             # AuthController: Xử lý login/logout, token
│   │   ├── alert_controller.py            # AlertController: CRUD cảnh báo
│   │   ├── traffic_controller.py          # TrafficController: API dữ liệu traffic (charts)
│   │   └── __init__.py
│   │
│   ├── models/                            # Model (ORM SQLAlchemy)
│   │   ├── user.py                        # User: Lưu user, mật khẩu hash
│   │   ├── alert.py                       # Alert: Lưu sự kiện IDS phát hiện
│   │   ├── traffic.py                     # Traffic: Lưu dữ liệu traffic/flows
│   │   └── __init__.py
│   │
│   ├── views/                             # View (HTML/CSS/JS)
│   │   ├── templates/
│   │   │   ├── base.html                  # Layout chung
│   │   │   ├── login.html                 # Form đăng nhập
│   │   │   ├── dashboard.html             # Dashboard chính
│   │   │   └── alerts.html                # Trang hiển thị alerts
│   │   └── static/
│   │       ├── css/                       # CSS
│   │       ├── js/                        # JS
│   │       └── images/                    # Icon/logo
│   │
│   ├── auth/
│   │   ├── authenticator.py               # Class Authenticator: Kiểm tra thông tin đăng nhập
│   │   └── jwt_manager.py                 # Class JWTManager: Sinh/validate JWT token
│   │
│   ├── realtime/
│   │   ├── socket_handler.py              # Class SocketHandler: Quản lý WebSocket/SSE
│   │   └── events.py                      # Class Events: Định nghĩa loại sự kiện real-time
│   │
│   ├── middleware.py                      # Middleware (auth, logging, rate limit…)
│   ├── app.py                             # Flask init + register blueprint
│   ├── routes.py                          # Mapping URL → Controller
│   └── __init__.py
│
├── common/                                # Tài nguyên dùng chung
│   ├── observability/
│   │   ├── metrics_exporter.py            # Export Prometheus metrics
│   │   └── structured_logger.py           # Logger JSON/structured logs
│   ├── secrets_manager.py                 # Class SecretsManager: Load secrets an toàn
│   ├── database.py                        # Class Database: Init SQLAlchemy engine/session
│   ├── logger.py                          # Class Logger: Logging chung
│   ├── utils.py                           # Hàm tiện ích chung
│   └── config_loader.py                   # Class ConfigLoader: Load config YAML/ENV
│
├── storage/                               # Dữ liệu, model ML
│   ├── models/
│   │   ├── manifest.json                  # Manifest mô tả version model
│   │   └── isolation_forest_v1.pkl        # Model ML (pickle)
│   ├── datasets/                          # Datasets dùng huấn luyện
│   └── migrations/
│       ├── alembic.ini                    # Alembic config
│       └── versions/
│           └── 0001_create_core_tables.py # Migration đầu tiên tạo bảng
│
├── tests/                                 # Test
│   ├── unit/                              # Unit tests (test từng module)
│   │   ├── test_packet_capture.py
│   │   ├── test_feature_extractor.py
│   │   └── test_rule_engine.py
│   ├── integration/                       # Integration tests (nhiều module cùng nhau)
│   │   └── test_api_endpoints.py
│   └── e2e/                               # End-to-End tests
│       ├── test_end_to_end.py             # Test full pipeline từ packet → alert
│       └── attack_simulations/
│           ├── port_scan.py               # Mô phỏng tấn công port scan
│           └── ssh_bruteforce.py          # Mô phỏng SSH bruteforce
│
├── config/
│   ├── main_config.yaml                   # Cấu hình tổng thể
│   ├── detector_config.yaml               # Cấu hình detector
│   └── secrets/
│       ├── .env.development               # ENV local (bỏ qua git)
│       └── .env.production.template       # Template ENV production
│
├── .github/
│   └── workflows/
│       ├── ci.yml                         # CI test & lint khi push/PR
│       └── codeql-analysis.yml            # GitHub CodeQL security scan
│
├── docker-compose.yml                     # Chạy multi-service (agent, flask, db, etc.)
├── Dockerfile                             # Docker cho dashboard (Flask/Gunicorn)
├── requirements.txt                       # Python deps
├── main.py                                # Entry point để run IDS pipeline
├── .env.template
├── .gitignore
└── README.md
