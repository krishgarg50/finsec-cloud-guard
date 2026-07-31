Literature Survey
24BIT0535
Topic: Explainable Cloud Misconfiguration Detection for Financial Institutions
Course: BCSE355L - Cloud Architecture Design
Paper	Method	Dataset	Advantages	Limitations	Research Gap
1. Transparency and Privacy: The Role of Explainable AI and Federated Learning in Financial Fraud Detection (IEEE Access, 2024)	Proposes a Federated Learning (FL) framework combined with a Deep Neural Network (DNN) for fraud detection. Each institution trains locally and shares only model updates with a central server, avoiding raw data sharing. Explainable AI (XAI) techniques make model decisions interpretable for analysts and auditors, improving trust while complying with privacy regulations.	Realistic financial transaction datasets with highly imbalanced fraud samples, evaluated under privacy-preserving collaborative learning rather than centralized data sharing.	●	Preserves customer privacy through federated learning.
●	Achieves high fraud detection performance despite data imbalance.
●	Provides explainable predictions using XAI.
●	Suitable for multi-bank collaboration without violating data protection laws.
●	Demonstrates practical deployment through a web-based prototype.	●	Focuses on fraud detection instead of cloud infrastructure security.
●	Does not analyze cloud IAM, storage, network, or configuration vulnerabilities.
●	Explainability is limited to fraud prediction rather than cloud risk analysis.
●	Computational overhead increases with federated training.	The proposed framework does not address cloud misconfiguration detection, which is one of the leading causes of cloud security breaches. Future work should integrate explainable AI with AWS configuration monitoring (IAM policies, S3 bucket permissions, Security Groups, etc.) so that security administrators receive both accurate detection and understandable explanations.
2. Towards Transparent AI-Powered Cybersecurity in Financial Systems (IEEE ICDMW, 2024)	Combines Artificial Intelligence, Federated Learning, and Explainable AI to improve cybersecurity monitoring in financial environments. AI models identify malicious activity from distributed security data, while explainability techniques help analysts understand why an alert is generated. The framework supports privacy-preserving collaboration among multiple organizations.	Financial cybersecurity logs and network traffic collected from multiple institutions in a federated setting, emphasizing collaborative threat detection while maintaining data privacy.	●	Improves transparency of AI-based cybersecurity alerts.
●	Preserves institutional privacy through federated learning.
●	Enables collaborative threat intelligence sharing.
●	Reduces dependence on centralized datasets.
●	Supports regulatory compliance through interpretable decisions.	●	Detects cyberattacks but not cloud configuration errors.
●	Limited focus on cloud-native platforms such as AWS or Azure.
●	Does not include automated cloud compliance validation.
●	Explainability is centered on intrusion detection rather than infrastructure security.	Existing systems mainly respond after suspicious activities occur. There is still no explainable framework capable of predicting cloud misconfigurations before attackers exploit them, especially for financial cloud infrastructures governed by strict compliance requirements.
3. Misconfiguration Prevention and Error Cause Detection for Distributed-Cloud Applications (2024)	Introduces a configuration validation framework that analyzes distributed-cloud application configurations before deployment. Using schema validation, dependency checking, and configuration comparison, it identifies invalid or conflicting settings and traces the root cause of deployment failures.	Distributed cloud application configuration files collected from cloud-native deployments, focused on configuration correctness rather than security incidents.	●	Prevents deployment failures caused by configuration errors.
●	Automatically identifies root causes of configuration problems.
●	Improves reliability of distributed-cloud applications.
●	Reduces debugging time for cloud administrators.
●	Useful during DevOps deployment pipelines.	●	Uses rule-based validation rather than machine learning.
●	No explainable AI module.
●	Not designed specifically for financial institutions.
●	Does not prioritize security risks associated with misconfigurations.	Future research should combine machine learning, Explainable AI, and cloud security posture management so that the system not only detects invalid configurations but also predicts risky security misconfigurations and explains their potential impact on sensitive financial services.
4. Explainable Artificial Intelligence (XAI) in Finance: A Systematic Literature Review (Springer, 2024)	Systematic review analyzing the application of Explainable AI techniques such as SHAP, LIME, attention mechanisms, feature importance analysis, and rule-based explanations across finance-related AI applications including fraud detection, credit scoring, insurance, and investment analytics. Identifies current trends and research challenges.	Review of more than one hundred published finance-related AI studies from multiple journals and conferences; survey-based, no single experimental dataset.	●	Comprehensive overview of XAI methods in finance.
●	Identifies strengths and weaknesses of major explanation techniques.
●	Highlights regulatory importance of interpretable AI.
●	Useful reference for selecting suitable XAI algorithms.
●	Provides future research directions.	●	Does not propose or evaluate a new model.
●	No cloud security implementation.
●	Does not address cloud configuration management.
●	No AWS architecture or deployment discussion.	Although explainable AI is widely used in financial analytics, very little research combines XAI with cloud security management. Future work should develop explainable cloud security systems capable of interpreting configuration risks in financial cloud environments while satisfying compliance requirements.
5. Advancing Credit Card Fraud Detection Through Explainable Machine Learning Methods (IEEE, 2024)	Evaluates several machine learning algorithms including Decision Trees, Random Forest, Support Vector Machine (SVM), and Logistic Regression for credit card fraud detection. Explainability methods are incorporated to identify influential transaction features and justify prediction outcomes, making fraud analysis more transparent for investigators.	Credit card transaction dataset containing both legitimate and fraudulent transactions with highly imbalanced class distribution.	●	High fraud detection accuracy.
●	Better model transparency using explainability techniques.
●	Helps analysts understand important fraud indicators.
●	Easier regulatory compliance through interpretable predictions.
●	Supports practical financial fraud investigation.	●	Limited to transaction-level fraud detection.
●	Does not monitor cloud infrastructure.
●	No cloud deployment architecture.
●	Explainability focuses only on transaction features rather than cloud resources.	Current research explains why a financial transaction is fraudulent, but does not explain why a cloud configuration is insecure. Integrating explainable cloud misconfiguration detection with financial fraud prevention would provide organizations with both infrastructure-level and application-level security intelligence.


