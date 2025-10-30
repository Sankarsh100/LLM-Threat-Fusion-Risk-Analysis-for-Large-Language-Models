"""
LLM Threat Fusion: Comprehensive Risk Analysis Framework
for Large Language Model Deployments

A structured approach to identifying, analyzing, and mitigating security risks
in LLM systems across enterprise environments.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import json
import os
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

class LLMThreatAnalyzer:
    """
    Comprehensive threat analysis framework for Large Language Model deployments
    """
    
    def __init__(self):
        self.threats = self._initialize_threat_database()
        self.risk_scores = {}
        self.mitigation_strategies = self._initialize_mitigations()
        
    def _initialize_threat_database(self) -> pd.DataFrame:
        """
        Initialize comprehensive threat database with OWASP LLM Top 10 and additional threats
        """
        threats_data = [
            {
                'threat_id': 'LLM01',
                'threat_name': 'Prompt Injection',
                'category': 'Input Manipulation',
                'severity': 'Critical',
                'likelihood': 'High',
                'impact': 'High',
                'description': 'Adversarial inputs designed to manipulate LLM behavior and bypass safety controls',
                'attack_vectors': ['Direct injection', 'Indirect injection via documents', 'Cross-prompt attacks'],
                'affected_components': ['User input processing', 'System prompts', 'Context management'],
                'cvss_score': 9.1
            },
            {
                'threat_id': 'LLM02',
                'threat_name': 'Insecure Output Handling',
                'category': 'Output Security',
                'severity': 'High',
                'likelihood': 'High',
                'impact': 'High',
                'description': 'Inadequate validation of LLM outputs leading to downstream vulnerabilities',
                'attack_vectors': ['XSS via generated content', 'SQL injection through outputs', 'Code injection'],
                'affected_components': ['Output validation', 'Content rendering', 'API responses'],
                'cvss_score': 8.5
            },
            {
                'threat_id': 'LLM03',
                'threat_name': 'Training Data Poisoning',
                'category': 'Model Integrity',
                'severity': 'Critical',
                'likelihood': 'Medium',
                'impact': 'Critical',
                'description': 'Manipulation of training data to introduce backdoors or biases',
                'attack_vectors': ['Supply chain attacks', 'Malicious data injection', 'Adversarial examples'],
                'affected_components': ['Training pipeline', 'Data sources', 'Model weights'],
                'cvss_score': 8.8
            },
            {
                'threat_id': 'LLM04',
                'threat_name': 'Model Denial of Service',
                'category': 'Availability',
                'severity': 'High',
                'likelihood': 'High',
                'impact': 'Medium',
                'description': 'Resource exhaustion attacks targeting LLM inference',
                'attack_vectors': ['Long input sequences', 'Computationally expensive queries', 'Rate limit bypass'],
                'affected_components': ['Inference engine', 'Resource management', 'API endpoints'],
                'cvss_score': 7.5
            },
            {
                'threat_id': 'LLM05',
                'threat_name': 'Supply Chain Vulnerabilities',
                'category': 'Dependencies',
                'severity': 'High',
                'likelihood': 'Medium',
                'impact': 'High',
                'description': 'Compromised third-party models, plugins, or training data',
                'attack_vectors': ['Malicious model repositories', 'Compromised dependencies', 'Plugin vulnerabilities'],
                'affected_components': ['Model sources', 'External plugins', 'Data pipelines'],
                'cvss_score': 8.2
            },
            {
                'threat_id': 'LLM06',
                'threat_name': 'Sensitive Information Disclosure',
                'category': 'Data Leakage',
                'severity': 'Critical',
                'likelihood': 'High',
                'impact': 'Critical',
                'description': 'Unintended exposure of PII, credentials, or proprietary information',
                'attack_vectors': ['Training data memorization', 'Prompt extraction', 'Context leakage'],
                'affected_components': ['Model memory', 'Context windows', 'Output filtering'],
                'cvss_score': 9.3
            },
            {
                'threat_id': 'LLM07',
                'threat_name': 'Insecure Plugin Design',
                'category': 'Integration Security',
                'severity': 'High',
                'likelihood': 'Medium',
                'impact': 'High',
                'description': 'Vulnerabilities in LLM plugins enabling unauthorized access or actions',
                'attack_vectors': ['Plugin injection', 'Privilege escalation', 'API abuse'],
                'affected_components': ['Plugin architecture', 'Authorization systems', 'Function calling'],
                'cvss_score': 8.0
            },
            {
                'threat_id': 'LLM08',
                'threat_name': 'Excessive Agency',
                'category': 'Authorization',
                'severity': 'High',
                'likelihood': 'Medium',
                'impact': 'High',
                'description': 'LLM granted excessive permissions leading to unauthorized actions',
                'attack_vectors': ['Privilege abuse', 'Unintended command execution', 'System manipulation'],
                'affected_components': ['Permission management', 'Action validators', 'Access controls'],
                'cvss_score': 7.8
            },
            {
                'threat_id': 'LLM09',
                'threat_name': 'Overreliance',
                'category': 'Human Factors',
                'severity': 'Medium',
                'likelihood': 'High',
                'impact': 'Medium',
                'description': 'Excessive trust in LLM outputs without verification',
                'attack_vectors': ['Misinformation propagation', 'Hallucination exploitation', 'Decision automation'],
                'affected_components': ['User interface', 'Decision workflows', 'Output validation'],
                'cvss_score': 6.5
            },
            {
                'threat_id': 'LLM10',
                'threat_name': 'Model Theft',
                'category': 'Intellectual Property',
                'severity': 'High',
                'likelihood': 'Medium',
                'impact': 'High',
                'description': 'Unauthorized access to or extraction of proprietary model weights',
                'attack_vectors': ['Model extraction attacks', 'API abuse', 'Side-channel attacks'],
                'affected_components': ['Model serving', 'API rate limits', 'Access controls'],
                'cvss_score': 7.7
            },
            {
                'threat_id': 'LLM11',
                'threat_name': 'Model Bias and Fairness',
                'category': 'Ethical Risks',
                'severity': 'High',
                'likelihood': 'High',
                'impact': 'Medium',
                'description': 'Discriminatory outputs based on protected characteristics',
                'attack_vectors': ['Biased training data', 'Amplification of stereotypes', 'Unfair decision-making'],
                'affected_components': ['Training data', 'Model architecture', 'Output generation'],
                'cvss_score': 7.2
            },
            {
                'threat_id': 'LLM12',
                'threat_name': 'Jailbreaking',
                'category': 'Safety Controls',
                'severity': 'Critical',
                'likelihood': 'High',
                'impact': 'High',
                'description': 'Bypassing safety guardrails and content filters',
                'attack_vectors': ['Adversarial prompts', 'Encoding tricks', 'Role-play attacks'],
                'affected_components': ['Content filters', 'Safety layers', 'System prompts'],
                'cvss_score': 8.7
            }
        ]
        
        return pd.DataFrame(threats_data)
    
    def _initialize_mitigations(self) -> Dict:
        """
        Initialize comprehensive mitigation strategies for each threat
        """
        mitigations = {
            'LLM01': {
                'preventive': [
                    'Implement input validation and sanitization',
                    'Use prompt templates with clear boundaries',
                    'Apply instruction hierarchy (system > user)',
                    'Implement context isolation between sessions',
                    'Deploy adversarial prompt detection'
                ],
                'detective': [
                    'Monitor for anomalous prompt patterns',
                    'Log all user interactions',
                    'Implement behavioral analytics',
                    'Real-time injection detection'
                ],
                'responsive': [
                    'Automatic session termination on detection',
                    'User account flagging',
                    'Incident response procedures',
                    'Forensic logging'
                ]
            },
            'LLM02': {
                'preventive': [
                    'Implement output encoding and sanitization',
                    'Use Content Security Policy (CSP)',
                    'Apply output validation schemas',
                    'Sandbox LLM-generated code execution',
                    'Implement output length limits'
                ],
                'detective': [
                    'Output scanning for malicious patterns',
                    'Monitor downstream system errors',
                    'Log output validation failures'
                ],
                'responsive': [
                    'Quarantine suspicious outputs',
                    'Alert security teams',
                    'Rollback affected changes'
                ]
            },
            'LLM03': {
                'preventive': [
                    'Verify data source integrity',
                    'Implement data validation pipelines',
                    'Use cryptographic signatures',
                    'Apply anomaly detection in training data',
                    'Maintain data provenance records'
                ],
                'detective': [
                    'Model behavior monitoring',
                    'Statistical analysis of outputs',
                    'Backdoor detection techniques',
                    'Regular model audits'
                ],
                'responsive': [
                    'Model rollback procedures',
                    'Retraining with verified data',
                    'Incident investigation protocols'
                ]
            },
            'LLM04': {
                'preventive': [
                    'Implement rate limiting',
                    'Set input length restrictions',
                    'Deploy resource quotas per user',
                    'Use caching mechanisms',
                    'Implement request complexity analysis'
                ],
                'detective': [
                    'Monitor resource utilization',
                    'Detect abnormal query patterns',
                    'Track response times'
                ],
                'responsive': [
                    'Automatic throttling',
                    'IP-based blocking',
                    'Graceful degradation',
                    'Incident response activation'
                ]
            },
            'LLM05': {
                'preventive': [
                    'Verify model checksums',
                    'Use trusted model repositories',
                    'Implement dependency scanning',
                    'Maintain software bill of materials (SBOM)',
                    'Apply zero-trust principles'
                ],
                'detective': [
                    'Continuous vulnerability scanning',
                    'Monitor for supply chain alerts',
                    'Audit third-party components'
                ],
                'responsive': [
                    'Patch management procedures',
                    'Component isolation',
                    'Incident response for compromises'
                ]
            },
            'LLM06': {
                'preventive': [
                    'Implement data loss prevention (DLP)',
                    'Use differential privacy techniques',
                    'Apply output filtering for PII',
                    'Implement context length limits',
                    'Data anonymization in training',
                    'Secure prompt engineering practices'
                ],
                'detective': [
                    'Monitor for sensitive data patterns',
                    'Regular privacy audits',
                    'Log analysis for leakage indicators'
                ],
                'responsive': [
                    'Automatic redaction of sensitive info',
                    'User notification procedures',
                    'Breach response protocols'
                ]
            },
            'LLM07': {
                'preventive': [
                    'Implement plugin sandboxing',
                    'Apply principle of least privilege',
                    'Use API authentication and authorization',
                    'Validate plugin inputs/outputs',
                    'Maintain plugin allowlists'
                ],
                'detective': [
                    'Monitor plugin behavior',
                    'Audit plugin permissions',
                    'Log plugin API calls'
                ],
                'responsive': [
                    'Disable compromised plugins',
                    'Rollback plugin changes',
                    'Security incident procedures'
                ]
            },
            'LLM08': {
                'preventive': [
                    'Implement granular permission controls',
                    'Apply action approval workflows',
                    'Use capability-based security',
                    'Implement transaction limits',
                    'Deploy authorization policies'
                ],
                'detective': [
                    'Monitor for unauthorized actions',
                    'Audit permission usage',
                    'Track high-risk operations'
                ],
                'responsive': [
                    'Automatic permission revocation',
                    'Action rollback mechanisms',
                    'Security escalation procedures'
                ]
            },
            'LLM09': {
                'preventive': [
                    'User education and training',
                    'Implement confidence scoring',
                    'Display uncertainty indicators',
                    'Require human verification for critical actions',
                    'Deploy fact-checking mechanisms'
                ],
                'detective': [
                    'Monitor decision outcomes',
                    'Track accuracy metrics',
                    'Collect user feedback'
                ],
                'responsive': [
                    'Correction procedures',
                    'User notification of errors',
                    'Incident review processes'
                ]
            },
            'LLM10': {
                'preventive': [
                    'Implement API rate limiting',
                    'Use model watermarking',
                    'Apply query complexity limits',
                    'Deploy access controls',
                    'Implement query response obfuscation'
                ],
                'detective': [
                    'Monitor for extraction patterns',
                    'Analyze query sequences',
                    'Track unusual API usage'
                ],
                'responsive': [
                    'Account suspension',
                    'Legal action procedures',
                    'Model redeployment with protections'
                ]
            },
            'LLM11': {
                'preventive': [
                    'Diverse training data curation',
                    'Bias detection in training',
                    'Implement fairness constraints',
                    'Regular bias audits',
                    'Use debiasing techniques',
                    'Diverse testing datasets'
                ],
                'detective': [
                    'Monitor outputs for bias indicators',
                    'A/B testing across demographics',
                    'Continuous fairness evaluation'
                ],
                'responsive': [
                    'Model retraining',
                    'Output correction mechanisms',
                    'Transparency reporting'
                ]
            },
            'LLM12': {
                'preventive': [
                    'Multi-layer content filtering',
                    'Adversarial training',
                    'Robust system prompts',
                    'Input/output alignment checks',
                    'Constitutional AI principles'
                ],
                'detective': [
                    'Monitor for jailbreak attempts',
                    'Pattern analysis of suspicious prompts',
                    'Real-time safety scoring'
                ],
                'responsive': [
                    'Session termination',
                    'User warnings and blocks',
                    'Safety system updates',
                    'Incident documentation'
                ]
            }
        }
        
        return mitigations
    
    def calculate_risk_score(self, threat_id: str, 
                           control_effectiveness: float = 0.5) -> Dict:
        """
        Calculate comprehensive risk score using CVSS-inspired methodology
        
        Args:
            threat_id: Threat identifier
            control_effectiveness: Effectiveness of current controls (0-1)
        
        Returns:
            Dictionary with risk metrics
        """
        threat = self.threats[self.threats['threat_id'] == threat_id].iloc[0]
        
        # Base severity mapping
        severity_scores = {
            'Critical': 10,
            'High': 8,
            'Medium': 5,
            'Low': 2
        }
        
        # Likelihood mapping
        likelihood_scores = {
            'High': 0.9,
            'Medium': 0.6,
            'Low': 0.3
        }
        
        base_score = severity_scores[threat['severity']]
        likelihood = likelihood_scores[threat['likelihood']]
        
        # Calculate inherent risk
        inherent_risk = base_score * likelihood
        
        # Calculate residual risk with controls
        residual_risk = inherent_risk * (1 - control_effectiveness)
        
        # Calculate risk reduction
        risk_reduction = inherent_risk - residual_risk
        
        return {
            'threat_id': threat_id,
            'threat_name': threat['threat_name'],
            'base_severity': base_score,
            'likelihood': likelihood,
            'inherent_risk': round(inherent_risk, 2),
            'control_effectiveness': control_effectiveness,
            'residual_risk': round(residual_risk, 2),
            'risk_reduction': round(risk_reduction, 2),
            'risk_level': self._categorize_risk(residual_risk)
        }
    
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize risk based on score"""
        if risk_score >= 7:
            return 'Critical'
        elif risk_score >= 5:
            return 'High'
        elif risk_score >= 3:
            return 'Medium'
        else:
            return 'Low'
    
    def generate_threat_matrix(self) -> pd.DataFrame:
        """
        Generate threat likelihood vs impact matrix
        """
        likelihood_map = {'Low': 1, 'Medium': 2, 'High': 3}
        impact_map = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        
        matrix_data = []
        for _, threat in self.threats.iterrows():
            matrix_data.append({
                'threat_id': threat['threat_id'],
                'threat_name': threat['threat_name'],
                'likelihood_score': likelihood_map.get(threat['likelihood'], 2),
                'impact_score': impact_map.get(threat['impact'], 2),
                'category': threat['category']
            })
        
        return pd.DataFrame(matrix_data)
    
    def analyze_all_threats(self, control_effectiveness_map: Dict = None) -> pd.DataFrame:
        """
        Analyze all threats with risk scoring
        """
        if control_effectiveness_map is None:
            # Default control effectiveness for each threat
            control_effectiveness_map = {
                threat_id: 0.5 for threat_id in self.threats['threat_id']
            }
        
        results = []
        for threat_id in self.threats['threat_id']:
            effectiveness = control_effectiveness_map.get(threat_id, 0.5)
            risk_data = self.calculate_risk_score(threat_id, effectiveness)
            results.append(risk_data)
        
        return pd.DataFrame(results)
    
    def visualize_threat_landscape(self, output_dir='visualizations'):
        """
        Create comprehensive threat landscape visualizations as separate files
        """
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 1. Threat Distribution by Severity
        fig1, ax1 = plt.subplots(figsize=(8, 6))
        severity_counts = self.threats['severity'].value_counts()
        colors = {'Critical': '#d62728', 'High': '#ff7f0e', 'Medium': '#ffbb00', 'Low': '#2ca02c'}
        severity_colors = [colors[s] for s in severity_counts.index]
        ax1.pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                colors=severity_colors, startangle=90)
        ax1.set_title('Threat Distribution by Severity', fontweight='bold', fontsize=14)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/01_threat_distribution_by_severity.png', dpi=300, bbox_inches='tight')
        plt.close()

        # 2. CVSS Scores by Threat with Category Colors
        fig2, ax2 = plt.subplots(figsize=(12, 8))

        # Define category colors
        category_colors = {
            'Input Manipulation': '#e74c3c',
            'Output Security': '#3498db',
            'Model Integrity': '#2ecc71',
            'Availability': '#f39c12',
            'Dependencies': '#9b59b6',
            'Data Leakage': '#e67e22',
            'Integration Security': '#1abc9c',
            'Authorization': '#34495e',
            'Human Factors': '#95a5a6',
            'Intellectual Property': '#d35400',
            'Ethical Risks': '#c0392b',
            'Safety Controls': '#e84393'
        }

        # Sort threats by CVSS score
        threats_sorted = self.threats.sort_values('cvss_score', ascending=True)

        # Create horizontal bar chart
        colors = [category_colors.get(cat, '#7f8c8d') for cat in threats_sorted['category']]
        bars = ax2.barh(range(len(threats_sorted)), threats_sorted['cvss_score'], color=colors, alpha=0.8, edgecolor='black', linewidth=0.5)

        # Add threat labels with severity indicators
        labels = []
        for _, row in threats_sorted.iterrows():
            severity_emoji = {'Critical': '[C]', 'High': '[H]', 'Medium': '[M]', 'Low': '[L]'}
            label = f"{row['threat_id']} - {row['threat_name'][:25]}... {severity_emoji.get(row['severity'], '')}"
            labels.append(label)

        ax2.set_yticks(range(len(threats_sorted)))
        ax2.set_yticklabels(labels, fontsize=9)
        ax2.set_xlabel('CVSS Score', fontsize=12, fontweight='bold')
        ax2.set_title('CVSS Scores by Threat (Colored by Category)', fontweight='bold', fontsize=14, pad=15)
        ax2.grid(axis='x', alpha=0.3, linestyle='--')

        # Add severity zone markers
        ax2.axvline(x=7.0, color='orange', linestyle='--', alpha=0.5, linewidth=2, label='High Risk (7.0+)')
        ax2.axvline(x=9.0, color='red', linestyle='--', alpha=0.5, linewidth=2, label='Critical Risk (9.0+)')

        # Add legend for categories (show unique categories only)
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor=category_colors[cat], edgecolor='black', label=cat)
                          for cat in threats_sorted['category'].unique()]
        ax2.legend(handles=legend_elements, bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=8, title='Threat Categories')

        # Add value labels on bars
        for i, (idx, row) in enumerate(threats_sorted.iterrows()):
            ax2.text(row['cvss_score'] + 0.1, i, f"{row['cvss_score']}",
                    va='center', fontsize=8, fontweight='bold')

        plt.tight_layout()
        plt.savefig(f'{output_dir}/02_cvss_by_threat_and_category.png', dpi=300, bbox_inches='tight')
        plt.close()

        # 3. CVSS Score Analysis by Severity Level
        fig3, ax3 = plt.subplots(figsize=(12, 8))

        # Group threats by severity
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        severity_colors_map = {'Critical': '#d62728', 'High': '#ff7f0e', 'Medium': '#ffbb00', 'Low': '#2ca02c'}

        # Prepare data for grouped display
        positions = []
        colors_scatter = []
        severity_labels = []
        x_positions = []

        for idx, severity in enumerate(severity_order):
            severity_threats = self.threats[self.threats['severity'] == severity]
            if len(severity_threats) > 0:
                # Create positions for this severity group
                base_x = idx * 3
                for i, (_, threat) in enumerate(severity_threats.iterrows()):
                    x_positions.append(base_x + (i * 0.3) - 0.3)
                    positions.append(threat['cvss_score'])
                    colors_scatter.append(severity_colors_map[severity])
                    severity_labels.append(severity)

        # Create scatter plot with jitter
        scatter = ax3.scatter(x_positions, positions, s=200, c=colors_scatter, alpha=0.7,
                             edgecolor='black', linewidth=1.5, zorder=3)

        # Add box plot overlay for each severity
        box_positions = []
        box_data = []
        box_colors = []

        for idx, severity in enumerate(severity_order):
            severity_threats = self.threats[self.threats['severity'] == severity]
            if len(severity_threats) > 0:
                box_positions.append(idx * 3)
                box_data.append(severity_threats['cvss_score'].values)
                box_colors.append(severity_colors_map[severity])

        # Create box plots
        bp = ax3.boxplot(box_data, positions=box_positions, widths=0.8,
                        patch_artist=True, showmeans=True, meanline=True,
                        boxprops=dict(alpha=0.3, linewidth=2),
                        whiskerprops=dict(linewidth=2),
                        capprops=dict(linewidth=2),
                        medianprops=dict(color='darkblue', linewidth=2.5),
                        meanprops=dict(color='red', linewidth=2, linestyle='--'))

        # Color the boxes
        for patch, color in zip(bp['boxes'], box_colors):
            patch.set_facecolor(color)

        # Add statistical annotations
        for idx, severity in enumerate(severity_order):
            severity_threats = self.threats[self.threats['severity'] == severity]
            if len(severity_threats) > 0:
                cvss_scores = severity_threats['cvss_score']
                mean_val = cvss_scores.mean()
                min_val = cvss_scores.min()
                max_val = cvss_scores.max()
                count = len(cvss_scores)

                # Add text annotation
                text_x = idx * 3
                text_y = max_val + 0.3
                stats_text = f"n={count}\nMin: {min_val:.1f}\nMax: {max_val:.1f}\nAvg: {mean_val:.1f}"
                ax3.text(text_x, text_y, stats_text, ha='center', va='bottom',
                        fontsize=9, bbox=dict(boxstyle='round', facecolor=severity_colors_map[severity],
                        alpha=0.2, edgecolor='black'))

        # Customize plot
        ax3.set_xlabel('Severity Level', fontsize=12, fontweight='bold')
        ax3.set_ylabel('CVSS Score', fontsize=12, fontweight='bold')
        ax3.set_title('CVSS Score Analysis by Severity Level', fontweight='bold', fontsize=14, pad=15)

        # Set x-axis labels
        ax3.set_xticks([i * 3 for i in range(len(box_positions))])
        ax3.set_xticklabels([severity_order[i] for i in range(len(box_positions))], fontsize=11, fontweight='bold')

        # Add horizontal grid
        ax3.grid(axis='y', alpha=0.3, linestyle='--')
        ax3.set_ylim(6, 10)

        # Add severity zone background shading
        ax3.axhspan(9.0, 10, alpha=0.1, color='red', label='Critical Zone (9.0+)')
        ax3.axhspan(7.0, 9.0, alpha=0.1, color='orange', label='High Zone (7.0-9.0)')
        ax3.axhspan(6.0, 7.0, alpha=0.1, color='yellow', label='Medium Zone (6.0-7.0)')

        # Add overall statistics line
        overall_mean = self.threats['cvss_score'].mean()
        ax3.axhline(overall_mean, color='darkred', linestyle=':', linewidth=2.5,
                   label=f'Overall Mean: {overall_mean:.1f}', zorder=1)

        # Legend
        ax3.legend(loc='upper right', fontsize=9, framealpha=0.9)

        # Add note about box plot elements
        note = "Box plot shows: median (blue line), mean (red dashed), quartiles (box), and range (whiskers)"
        fig3.text(0.5, 0.02, note, ha='center', fontsize=8, style='italic', color='gray')

        plt.tight_layout()
        plt.savefig(f'{output_dir}/03_cvss_analysis_by_severity.png', dpi=300, bbox_inches='tight')
        plt.close()

        # 4. Likelihood vs Impact Matrix
        fig4, ax4 = plt.subplots(figsize=(14, 10))
        matrix_df = self.generate_threat_matrix()
        
        # Create scatter plot
        colors_map = {
            'Input Manipulation': '#e74c3c',
            'Output Security': '#3498db',
            'Model Integrity': '#2ecc71',
            'Availability': '#f39c12',
            'Dependencies': '#9b59b6',
            'Data Leakage': '#e67e22',
            'Integration Security': '#1abc9c',
            'Authorization': '#34495e',
            'Human Factors': '#95a5a6',
            'Intellectual Property': '#d35400',
            'Ethical Risks': '#c0392b',
            'Safety Controls': '#e84393'
        }
        
        for category in matrix_df['category'].unique():
            mask = matrix_df['category'] == category
            ax4.scatter(matrix_df[mask]['likelihood_score'], 
                       matrix_df[mask]['impact_score'],
                       s=200, alpha=0.6, label=category,
                       color=colors_map.get(category, 'gray'))
        
        # Add threat labels
        for _, row in matrix_df.iterrows():
            ax4.annotate(row['threat_id'], 
                        (row['likelihood_score'], row['impact_score']),
                        fontsize=8, ha='center', va='center', fontweight='bold')
        
        ax4.set_xlabel('Likelihood', fontsize=13, fontweight='bold')
        ax4.set_ylabel('Impact', fontsize=13, fontweight='bold')
        ax4.set_title('Threat Likelihood vs Impact Matrix', fontsize=16, fontweight='bold', pad=20)
        ax4.set_xticks([1, 2, 3])
        ax4.set_xticklabels(['Low', 'Medium', 'High'], fontsize=11)
        ax4.set_yticks([1, 2, 3, 4])
        ax4.set_yticklabels(['Low', 'Medium', 'High', 'Critical'], fontsize=11)
        ax4.grid(True, alpha=0.3)
        ax4.legend(bbox_to_anchor=(1.02, 1), loc='upper left', fontsize=9)

        # Add risk zones
        ax4.axhline(y=2.5, color='orange', linestyle='--', alpha=0.3, linewidth=2)
        ax4.axvline(x=2, color='orange', linestyle='--', alpha=0.3, linewidth=2)
        ax4.fill_between([2, 3.5], 2.5, 4.5, alpha=0.1, color='red')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/04_likelihood_vs_impact_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()

        # 5. Top Threats by CVSS Score
        fig5, ax5 = plt.subplots(figsize=(10, 8))
        top_threats = self.threats.nlargest(8, 'cvss_score')
        colors_threat = ['#d62728' if x >= 9 else '#ff7f0e' if x >= 8 else '#ffbb00'
                        for x in top_threats['cvss_score']]
        ax5.barh(range(len(top_threats)), top_threats['cvss_score'], color=colors_threat)
        ax5.set_yticks(range(len(top_threats)))
        ax5.set_yticklabels([f"{row['threat_id']} - {row['threat_name'][:20]}..."
                             for _, row in top_threats.iterrows()], fontsize=9)
        ax5.set_xlabel('CVSS Score', fontsize=11)
        ax5.set_title('Top Threats by Severity (CVSS Score)', fontweight='bold', fontsize=14)
        ax5.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/05_top_threats_by_cvss.png', dpi=300, bbox_inches='tight')
        plt.close()

        # 6. Risk Assessment with Controls
        fig6, ax6 = plt.subplots(figsize=(14, 8))
        
        # Calculate risk scores
        control_scenarios = {
            'No Controls': 0.0,
            'Basic Controls': 0.3,
            'Standard Controls': 0.6,
            'Advanced Controls': 0.85
        }
        
        threat_ids = self.threats['threat_id'].tolist()[:6]  # Top 6 for visibility
        x = np.arange(len(threat_ids))
        width = 0.2
        
        for idx, (scenario, effectiveness) in enumerate(control_scenarios.items()):
            risks = [self.calculate_risk_score(tid, effectiveness)['residual_risk'] 
                    for tid in threat_ids]
            ax6.bar(x + idx * width, risks, width, label=scenario, alpha=0.8)
        
        ax6.set_xlabel('Threat ID', fontweight='bold', fontsize=12)
        ax6.set_ylabel('Residual Risk Score', fontweight='bold', fontsize=12)
        ax6.set_title('Risk Reduction Analysis: Impact of Security Controls',
                     fontsize=15, fontweight='bold', pad=15)
        ax6.set_xticks(x + width * 1.5)
        ax6.set_xticklabels(threat_ids, fontsize=10)
        ax6.legend(loc='upper right', fontsize=10)
        ax6.grid(axis='y', alpha=0.3)
        ax6.axhline(y=7, color='red', linestyle='--', alpha=0.5, linewidth=2)
        plt.tight_layout()
        plt.savefig(f'{output_dir}/06_risk_reduction_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()

        return output_dir
    
    def generate_mitigation_report(self, threat_id: str) -> str:
        """
        Generate detailed mitigation report for a specific threat
        """
        threat = self.threats[self.threats['threat_id'] == threat_id].iloc[0]
        mitigations = self.mitigation_strategies.get(threat_id, {})
        
        report = f"""
{'='*80}
THREAT MITIGATION REPORT
{'='*80}

Threat ID: {threat['threat_id']}
Threat Name: {threat['threat_name']}
Category: {threat['category']}
Severity: {threat['severity']}
CVSS Score: {threat['cvss_score']}

DESCRIPTION:
{threat['description']}

ATTACK VECTORS:
"""
        for vector in threat['attack_vectors']:
            report += f"  - {vector}\n"

        report += f"\nAFFECTED COMPONENTS:\n"
        for component in threat['affected_components']:
            report += f"  - {component}\n"
        
        report += f"\n{'='*80}\nMITIGATION STRATEGIES\n{'='*80}\n"
        
        for category, strategies in mitigations.items():
            report += f"\n{category.upper()} CONTROLS:\n"
            for idx, strategy in enumerate(strategies, 1):
                report += f"  {idx}. {strategy}\n"
        
        # Add risk calculation
        risk_data = self.calculate_risk_score(threat_id, control_effectiveness=0.6)
        report += f"\n{'='*80}\nRISK ASSESSMENT (with 60% control effectiveness)\n{'='*80}\n"
        report += f"Inherent Risk: {risk_data['inherent_risk']}\n"
        report += f"Residual Risk: {risk_data['residual_risk']}\n"
        report += f"Risk Reduction: {risk_data['risk_reduction']}\n"
        report += f"Risk Level: {risk_data['risk_level']}\n"
        
        return report
    
    def generate_executive_summary(self) -> str:
        """
        Generate executive summary of LLM threat landscape
        """
        total_threats = len(self.threats)
        critical_threats = len(self.threats[self.threats['severity'] == 'Critical'])
        high_threats = len(self.threats[self.threats['severity'] == 'High'])
        avg_cvss = self.threats['cvss_score'].mean()
        
        # Calculate overall risk with standard controls
        risk_analysis = self.analyze_all_threats({'LLM01': 0.6, 'LLM02': 0.6, 'LLM03': 0.5,
                                                  'LLM04': 0.7, 'LLM05': 0.5, 'LLM06': 0.6,
                                                  'LLM07': 0.6, 'LLM08': 0.6, 'LLM09': 0.4,
                                                  'LLM10': 0.5, 'LLM11': 0.5, 'LLM12': 0.6})
        
        high_risk_count = len(risk_analysis[risk_analysis['risk_level'].isin(['Critical', 'High'])])
        
        summary = f"""
{'='*80}
LLM THREAT FUSION: EXECUTIVE SUMMARY
{'='*80}

THREAT LANDSCAPE OVERVIEW
{'-'*80}

Total Identified Threats: {total_threats}
Critical Severity Threats: {critical_threats}
High Severity Threats: {high_threats}
Average CVSS Score: {avg_cvss:.1f}
High-Risk Items (Post-Controls): {high_risk_count}

KEY FINDINGS
{'-'*80}

1. CRITICAL THREATS REQUIRING IMMEDIATE ATTENTION:
   - Sensitive Information Disclosure (CVSS: 9.3)
   - Prompt Injection (CVSS: 9.1)
   - Training Data Poisoning (CVSS: 8.8)
   - Jailbreaking (CVSS: 8.7)

2. MOST VULNERABLE ATTACK SURFACES:
   - Input Processing & Validation
   - Output Handling & Rendering
   - Training Data Pipeline
   - Plugin Integration Points

3. PRIMARY THREAT CATEGORIES:
   - Input Manipulation: Advanced prompt injection techniques
   - Data Leakage: PII exposure and training data memorization
   - Model Integrity: Poisoning and backdoor attacks
   - Safety Controls: Guardrail bypass mechanisms

RISK POSTURE ASSESSMENT
{'-'*80}

With Standard Security Controls (60% effectiveness):
  - {high_risk_count} threats remain in High/Critical risk category
  - Residual risk concentrated in: Prompt Injection, Data Leakage, Bias
  - Control gaps identified in: Plugin security, Training pipeline, Output validation

STRATEGIC RECOMMENDATIONS
{'-'*80}

IMMEDIATE ACTIONS (0-30 days):
  1. Deploy prompt injection detection and filtering
  2. Implement comprehensive output sanitization
  3. Establish data loss prevention (DLP) controls
  4. Deploy rate limiting and resource quotas

SHORT-TERM PRIORITIES (30-90 days):
  1. Develop plugin security framework
  2. Implement model monitoring and anomaly detection
  3. Establish training data validation pipeline
  4. Deploy bias detection and mitigation controls

LONG-TERM INITIATIVES (90+ days):
  1. Develop comprehensive AI governance framework
  2. Implement red team testing program
  3. Build security operations playbooks
  4. Establish continuous compliance monitoring

COMPLIANCE CONSIDERATIONS
{'-'*80}

Regulatory Frameworks:
  - GDPR: Data protection and privacy requirements
  - SOC 2: Security controls and monitoring
  - NIST AI RMF: AI risk management framework
  - EU AI Act: High-risk AI system requirements
  - ISO 27001: Information security management

CONCLUSION
{'-'*80}

LLM deployments present significant security challenges requiring multi-layered
defense strategies. Organizations must adopt a proactive security posture with
continuous monitoring, robust controls, and regular assessment to mitigate risks
while enabling innovation.

The threat landscape is rapidly evolving, necessitating ongoing threat intelligence
gathering and adaptive security measures.

{'='*80}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}
"""
        return summary
    
    def export_threat_database(self, filename: str = 'llm_threats.csv'):
        """Export threat database to CSV"""
        output_path = filename
        self.threats.to_csv(output_path, index=False)
        print(f"[+] Threat database exported to {output_path}")
        return output_path
    
    def export_risk_analysis(self, filename: str = 'risk_analysis.csv'):
        """Export risk analysis to CSV"""
        risk_df = self.analyze_all_threats()
        output_path = filename
        risk_df.to_csv(output_path, index=False)
        print(f"[+] Risk analysis exported to {output_path}")
        return output_path


def main():
    """Main execution function"""
    
    print("="*80)
    print("LLM THREAT FUSION: COMPREHENSIVE RISK ANALYSIS")
    print("="*80)
    
    # Initialize analyzer
    analyzer = LLMThreatAnalyzer()
    
    # Generate executive summary
    print("\n" + analyzer.generate_executive_summary())
    
    # Create visualizations
    print("\n[*] Generating threat landscape visualizations...")
    output_dir = analyzer.visualize_threat_landscape()
    print(f"[+] All visualizations saved to '{output_dir}/' folder!")
    print("    - 01_threat_distribution_by_severity.png")
    print("    - 02_cvss_by_threat_and_category.png")
    print("    - 03_cvss_analysis_by_severity.png")
    print("    - 04_likelihood_vs_impact_matrix.png")
    print("    - 05_top_threats_by_cvss.png")
    print("    - 06_risk_reduction_analysis.png")

    # Generate individual threat reports
    print("\n[*] Generating detailed mitigation reports...")
    critical_threats = ['LLM01', 'LLM03', 'LLM06', 'LLM12']

    for threat_id in critical_threats:
        report = analyzer.generate_mitigation_report(threat_id)
        filename = f'mitigation_report_{threat_id.lower()}.txt'
        with open(filename, 'w') as f:
            f.write(report)
        print(f"  [+] {threat_id} report generated")

    # Export data
    print("\n[*] Exporting analysis data...")
    analyzer.export_threat_database()
    analyzer.export_risk_analysis()
    
    # Generate comparison table
    print("\n" + "="*80)
    print("RISK COMPARISON: NO CONTROLS VS STANDARD CONTROLS")
    print("="*80)
    
    risk_no_controls = analyzer.analyze_all_threats(
        {tid: 0.0 for tid in analyzer.threats['threat_id']}
    )
    risk_with_controls = analyzer.analyze_all_threats(
        {tid: 0.6 for tid in analyzer.threats['threat_id']}
    )
    
    comparison = pd.DataFrame({
        'Threat': risk_no_controls['threat_name'],
        'No Controls': risk_no_controls['residual_risk'],
        'With Controls': risk_with_controls['residual_risk'],
        'Reduction': risk_no_controls['residual_risk'] - risk_with_controls['residual_risk']
    })
    
    print(comparison.to_string(index=False))
    
    print("\n" + "="*80)
    print("[+] LLM Threat Analysis Complete!")
    print("="*80)
    print("\nGenerated outputs:")
    print("  - visualizations/ folder - 6 separate visualization charts")
    print("  - mitigation_report_*.txt - Detailed mitigation strategies (4 files)")
    print("  - llm_threats.csv - Complete threat database")
    print("  - risk_analysis.csv - Quantitative risk assessment")


if __name__ == "__main__":
    main()
