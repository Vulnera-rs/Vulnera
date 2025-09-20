### **The Blueprint: Technical Architecture & Design**

The blueprint outlines the "how" – the technical foundation of your new platform.

#### **1. Core Principles**
*   **Asynchronous & Non-blocking**: Every service will be built on Rust's async foundation (Tokio) to handle high throughput.
*   **Stateless Microservices**: All analysis services will be stateless, allowing for easy horizontal scaling. State will be managed by the Orchestrator or stored in a central database.
*   **Schema-Driven Development**: Communication is key. We will strictly define the schemas for all API requests and Kafka messages to ensure consistency.
*   **Infrastructure as Code (IaC)**: The entire platform, including Kafka and the services, will be defined in code (e.g., Kubernetes manifests, Helm charts) for repeatable deployments.

#### **2. Technology Stack**
*   **Language**: Rust (for performance, safety, and concurrency).
*   **Web Framework**: `axum` for the Orchestration Service API.
*   **Async Runtime**: `tokio`.
*   **Serialization**: `serde` (for JSON communication over Kafka and APIs).
*   **Message Broker**: Apache Kafka (or a managed equivalent like Redpanda, Confluent Cloud).
*   **Kafka Client**: `rdkafka-rust`.
*   **Database**: PostgreSQL (for the Orchestrator to track job status and for the Reporting engine to store historical data).
*   **Database Client**: `sqlx`.
*   **Containerization**: Docker.
*   **Orchestration**: Kubernetes (K8s).

#### **3. Data Contracts (API & Kafka Schemas)**

This is the most critical part of the blueprint. All services must adhere to these contracts.

**a. Orchestrator API Request (`POST /api/v1/analyze`)**
```json
{
  "source_type": "git", // or "file_upload", "s3_bucket"
  "source_uri": "https://github.com/my-org/my-project.git",
  "analysis_depth": "full", // or "dependencies_only", "fast_scan"
  "callback_url": "https://my-ci-cd.com/webhook/123" // Optional
}
```

**b. Kafka Message: `JobRequest` (Sent by Orchestrator)**
*   **Topic**: `sast_jobs`, `dependency_analysis_jobs`, etc.
*   **Payload Schema**:
```json
{
  "job_id": "uuid-v4-for-overall-scan",
  "project_id": "unique-identifier-for-project",
  "source_uri": "s3://path/to/cloned/repo", // Orchestrator clones git repo to a shared location
  "config": {
    // Module-specific configuration
    "language": "Java",
    "java_version": "17"
  }
}
```

**c. Kafka Message: `Finding` (Sent by all Analysis Microservices)**
*   **Topic**: `raw_analysis_findings`
*   **Payload Schema**:
```json
{
  "job_id": "uuid-v4-for-overall-scan",
  "project_id": "unique-identifier-for-project",
  "source_module": "DependencyAnalyzer", // or "SAST", "SecretDetection"
  "finding": {
    "type": "Vulnerability", // or "Secret", "LicenseViolation", "Misconfiguration"
    "rule_id": "CVE-2021-44228",
    "location": {
      "path": "pom.xml",
      "line": 85
    },
    "severity": "CRITICAL", // CRITICAL, HIGH, MEDIUM, LOW, INFO
    "confidence": "HIGH",
    "description": "Remote code execution in log4j-core",
    "recommendation": "Upgrade log4j-core to version 2.17.1 or later."
  }
}
```

**d. Kafka Message: `FinalReport` (Sent by Reporting Engine)**
*   **Topic**: `final_reports`
*   **Payload Schema**:
```json
{
  "job_id": "uuid-v4-for-overall-scan",
  "project_id": "unique-identifier-for-project",
  "status": "Completed", // or "Failed"
  "summary": {
    "total_findings": 127,
    "critical": 5,
    "high": 22,
    "medium": 60,
    "low": 40
  },
  "findings": [
    // Array of aggregated and de-duplicated 'Finding' objects
  ],
  "sbom_reference": "s3://path/to/project.cdx.json" // Link to SBOM if generated
}
```

---

### **The Roadmap: Phased Implementation Plan**

This roadmap breaks the project into manageable phases, each with clear goals and outcomes.

#### **Phase 1: Foundation & MVP**
**Goal**: Prove the core microservices architecture works using the existing Dependency Analyzer.
*   **Tasks**:
    1.  **Setup Infrastructure**: Deploy a Kafka cluster and a PostgreSQL database (using Docker Compose for local dev, K8s for staging).
    2.  **Develop Orchestration Service**:
        *   Create the `/api/v1/analyze` endpoint.
        *   Implement the initial "AI Model" as a simple rules engine (e.g., read file names like `package.json`, `pom.xml` to decide which analyzer to trigger).
        *   Implement a Kafka producer to send messages to `dependency_analysis_jobs`.
        *   Implement a Kafka consumer to listen for the `final_reports` topic.
    3.  **Refactor Dependency Analyzer**:
        *   Containerize the existing Vulnera codebase.
        *   Remove its API layer. Replace it with a Kafka consumer that listens to `dependency_analysis_jobs`.
        *   Modify its output to produce messages according to the `Finding` schema on the `raw_analysis_findings` topic.
    4.  **Develop Reporting & Recommendation Engine (V1)**:
        *   Create a new service that consumes from `raw_analysis_findings`.
        *   Implement basic aggregation logic (group findings by `job_id`).
        *   Produce a `FinalReport` message to the `final_reports` topic once all expected findings for a job are received (or after a timeout).
*   **Key Outcome**: A user can submit a Git repository via the API and receive a full dependency analysis report, all orchestrated through Kafka. The new architecture is validated end-to-end.

#### **Phase 2: Expanding Static Analysis Capabilities**
**Goal**: Add core static analysis modules that work directly on the source code.
*   **Tasks**:
    1.  **Develop SAST Microservice**:
        *   Choose a SAST engine (e.g., integrate an existing open-source tool like Semgrep, or build custom detectors for common vulnerabilities).
        *   Wrap it in a Rust service that consumes from `sast_jobs` and produces `Finding` messages.
    2.  **Develop Secret Detection Microservice**:
        *   Implement scanning logic using regex and entropy analysis.
        *   Wrap it in a Rust service that consumes from `secret_detection_jobs` and produces `Finding` messages.
    3.  **Enhance Orchestrator**: Update the rules engine to trigger these new modules for relevant projects.
    4.  **Enhance Reporting Engine**: Improve de-duplication and prioritization logic to handle findings from multiple sources.
*   **Key Outcome**: The platform can now perform comprehensive static analysis, finding both dependency vulnerabilities and flaws directly in the source code.

#### **Phase 3: Deepening Supply Chain Security**
**Goal**: Become a comprehensive Software Supply Chain security solution.
*   **Tasks**:
    1.  **Develop SBOM Generation Microservice**:
        *   Integrate tools like Syft or CycloneDX generators.
        *   This service will consume a job request and produce an SBOM file (stored in S3) and a message with its location.
    2.  **Develop License Compliance Microservice**:
        *   Use the dependency list from the Dependency Analyzer or an SBOM.
        *   Check licenses against a user-defined policy.
    3.  **Develop Malicious Package Detection Microservice**:
        *   Implement heuristics to identify suspicious packages (typosquatting, etc.).
*   **Key Outcome**: The platform provides deep insights into software supply chains, covering vulnerabilities, licenses, and potential threats beyond known CVEs.

#### **Phase 4: Runtime & Infrastructure Analysis**
**Goal**: Extend analysis beyond the codebase to running applications and cloud infrastructure. This is a significant expansion.
*   **Tasks**:
    1.  **Develop IaC/Container Security Microservice**:
        *   Integrate tools like `Checkov` or `Trivy` to scan Terraform, Dockerfiles, and K8s manifests.
    2.  **Develop DAST Microservice**:
        *   Integrate an open-source DAST engine like OWASP ZAP.
        *   The orchestrator will take a target URL as input and trigger this service post-deployment.
    3.  **Develop API Security Microservice**:
        *   A specialized DAST scanner focused on OpenAPI/Swagger specifications.
    4.  **(Optional/Advanced) Develop CSPM Microservice**:
        *   Requires read-only credentials to a cloud environment. Scans for live misconfigurations.
*   **Key Outcome**: The toolkit can now secure the entire lifecycle, from code to cloud, providing a holistic view of an application's security posture.

#### **Phase 5: Maturation & Intelligence**
**Goal**: Enhance the platform's intelligence, user experience, and advanced capabilities.
*   **Tasks**:
    1.  **Evolve the "AI Model"**: Move from a rules engine to a true machine learning model that can better predict which modules to run, prioritize findings based on project context, and even suggest code fixes.
    2.  **Develop a Web UI**: remake the frontend to visualize scan results, manage projects, and configure policies.
    3.  **Implement Fuzz Testing Microservice**: An advanced feature for finding deep, complex bugs.
    4.  **Performance Tuning & Optimization**: Continuously monitor and scale the platform.
*   **Key Outcome**: The platform becomes a market-leading, intelligent security analysis solution.
