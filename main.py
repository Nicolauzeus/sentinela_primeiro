import sys
import os
import logging
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QProgressBar, QLineEdit, QScrollArea,
    QMessageBox, QListWidget, QTextEdit, QFileDialog
)
from PyQt6.QtGui import QPixmap, QPalette, QColor, QFont, QIcon
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSize, QThread, pyqtSignal
from fpdf import FPDF
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas

# Importações dos módulos de detecção de vulnerabilidade
from modules import (
    xss_tool,
    dork_tool,
    traversal_tool,
    command_injection,
    sensitive_data,
    misconfiguration,
    sfps
)

# Configuração de logging
logging.basicConfig(
    filename='sentinela.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class ScanThread(QThread):
    update_progress = pyqtSignal(int)
    found_vulnerability = pyqtSignal(dict)  # {type, severity, details}
    scan_completed = pyqtSignal(bool, str)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    
    def run(self):
        try:
            # Executa todos os scans sequencialmente
            self.scan_xss()
            self.update_progress.emit(15)
            
            self.scan_dork()
            self.update_progress.emit(30)
            
            self.scan_traversal()
            self.update_progress.emit(45)
            
            self.scan_command_injection()
            self.update_progress.emit(60)
            
            self.scan_sensitive_data()
            self.update_progress.emit(75)
            
            self.scan_misconfiguration()
            self.update_progress.emit(90)
            
            self.scan_sfps()
            self.update_progress.emit(100)
            
            self.scan_completed.emit(True, "Scan concluído com sucesso")
        except Exception as e:
            logging.error(f"Erro durante o scan: {str(e)}")
            self.scan_completed.emit(False, f"Erro: {str(e)}")
    
    def scan_xss(self):
        try:
            results = xss_tool.run_xss(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'XSS',
                    'severity': vuln.get('gravidade', 'Média'),
                    'details': vuln.get('detalhes', 'Vulnerabilidade XSS encontrada')
                })
        except Exception as e:
            logging.error(f"Erro no scan XSS: {str(e)}")
    
    def scan_dork(self):
        try:
            results = dork_tool.scan_dorks(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Google Dork',
                    'severity': vuln.get('gravidade', 'Média'),
                    'details': vuln.get('detalhes', 'Informação sensível encontrada')
                })
        except Exception as e:
            logging.error(f"Erro no scan Dork: {str(e)}")
    
    def scan_traversal(self):
        try:
            results = traversal_tool.scan_traversal(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Directory Traversal',
                    'severity': vuln.get('gravidade', 'Alta'),
                    'details': vuln.get('detalhes', 'Possível vulnerabilidade de traversal')
                })
        except Exception as e:
            logging.error(f"Erro no scan Directory Traversal: {str(e)}")
    
    def scan_command_injection(self):
        try:
            results = command_injection.scan_command_injection(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Command Injection',
                    'severity': vuln.get('gravidade', 'Alta'),
                    'details': vuln.get('detalhes', 'Possível vulnerabilidade de injeção de comandos')
                })
        except Exception as e:
            logging.error(f"Erro no scan Command Injection: {str(e)}")
    
    def scan_sensitive_data(self):
        try:
            results = sensitive_data.scan_sensitive_data(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Sensitive Data',
                    'severity': vuln.get('gravidade', 'Média'),
                    'details': vuln.get('detalhes', 'Dados sensíveis expostos')
                })
        except Exception as e:
            logging.error(f"Erro no scan Sensitive Data: {str(e)}")
    
    def scan_misconfiguration(self):
        try:
            results = misconfiguration.scan_misconfiguration(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Misconfiguration',
                    'severity': vuln.get('gravidade', 'Baixa'),
                    'details': vuln.get('detalhes', 'Possível má configuração de segurança')
                })
        except Exception as e:
            logging.error(f"Erro no scan Misconfiguration: {str(e)}")
    
    def scan_sfps(self):
        try:
            results = sfps.scan_subdomains_and_ports(self.domain)
            for vuln in results:
                self.found_vulnerability.emit({
                    'type': 'Subdomains/Ports',
                    'severity': vuln.get('gravidade', 'Informação'),
                    'details': vuln.get('detalhes', 'Subdomínio ou porta encontrada')
                })
        except Exception as e:
            logging.error(f"Erro no scan SFPS: {str(e)}")

class AnimatedButton(QPushButton):
    def __init__(self, text, function=None):
        super().__init__(text)
        self.default_size = QSize(200, 60)
        self.setMinimumSize(self.default_size)
        self.setMaximumSize(self.default_size)
        
        if function:
            self.clicked.connect(function)
        
        self.animation = QPropertyAnimation(self, b"size")
        self.animation.setDuration(250)
        self.animation.setEasingCurve(QEasingCurve.Type.OutQuad)
    
    def enterEvent(self, event):
        if self.size() == self.default_size:
            self.animation.stop()
            self.animation.setStartValue(self.default_size)
            self.animation.setEndValue(QSize(self.default_size.width() + 15, self.default_size.height() + 15))
            self.animation.start()
    
    def leaveEvent(self, event):
        self.animation.stop()
        self.animation.setStartValue(self.size())
        self.animation.setEndValue(self.default_size)
        self.animation.start()

class SentinelaPrimeiro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinela Primeiro - Bug Hunter")
        self.setGeometry(100, 100, 1200, 800)
        
        # Variáveis de estado
        self.current_theme = "Azul Escuro"
        self.vulnerabilities = []
        self.scan_thread = None
        
        # Configuração da interface
        self.init_ui()
        self.apply_theme()
    
    def init_ui(self):
        # Widget central e layout principal
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.main_layout = QHBoxLayout()
        self.central_widget.setLayout(self.main_layout)
        
        # Painel lateral (menu)
        self.init_side_panel()
        
        # Área de conteúdo (stacked widget)
        self.content_stack = QStackedWidget()
        self.main_layout.addWidget(self.content_stack)
        
        # Páginas da interface
        self.init_home_page()
        self.init_scan_page()
        self.init_results_page()
        self.init_help_page()
        self.init_about_page()
    
    def init_side_panel(self):
        side_panel = QWidget()
        side_panel.setFixedWidth(250)
        side_layout = QVBoxLayout()
        side_panel.setLayout(side_layout)
        
        # Logo
        logo = QLabel("Sentinela Primeiro")
        logo.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(logo)
        
        # Seletor de tema
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Azul Escuro", "Preto", "Branco"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        side_layout.addWidget(self.theme_combo)
        
        # Botões do menu
        self.btn_home = AnimatedButton("Início", lambda: self.content_stack.setCurrentWidget(self.home_page))
        self.btn_scan = AnimatedButton("Novo Scan", lambda: self.content_stack.setCurrentWidget(self.scan_page))
        self.btn_results = AnimatedButton("Resultados", lambda: self.content_stack.setCurrentWidget(self.results_page))
        self.btn_help = AnimatedButton("Ajuda", lambda: self.content_stack.setCurrentWidget(self.help_page))
        self.btn_about = AnimatedButton("Sobre", lambda: self.content_stack.setCurrentWidget(self.about_page))
        
        for btn in [self.btn_home, self.btn_scan, self.btn_results, self.btn_help, self.btn_about]:
            side_layout.addWidget(btn)
        
        side_layout.addStretch()
        
        # Versão
        version_label = QLabel("v2.0.0")
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(version_label)
        
        self.main_layout.addWidget(side_panel)
    
    def init_home_page(self):
        self.home_page = QWidget()
        layout = QVBoxLayout()
        self.home_page.setLayout(layout)
        
        # Conteúdo da página inicial
        welcome_label = QLabel("Bem-vindo ao Sentinela Primeiro")
        welcome_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(welcome_label)
        
        # Botão de início rápido
        quick_scan_btn = AnimatedButton("Iniciar Scan Rápido", lambda: self.content_stack.setCurrentWidget(self.scan_page))
        layout.addWidget(quick_scan_btn)
        
        self.content_stack.addWidget(self.home_page)
    
    def init_scan_page(self):
        self.scan_page = QWidget()
        layout = QVBoxLayout()
        self.scan_page.setLayout(layout)
        
        # Campo de entrada do domínio
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Digite o domínio para scan (ex: exemplo.com)")
        layout.addWidget(self.domain_input)
        
        # Botão de iniciar scan
        self.start_scan_btn = AnimatedButton("Iniciar Scan", self.start_scan)
        layout.addWidget(self.start_scan_btn)
        
        # Barra de progresso
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Área de log
        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        layout.addWidget(self.scan_log)
        
        self.content_stack.addWidget(self.scan_page)
    
    def init_results_page(self):
        self.results_page = QWidget()
        layout = QVBoxLayout()
        self.results_page.setLayout(layout)
        
        # Lista de vulnerabilidades
        self.vuln_list = QListWidget()
        layout.addWidget(self.vuln_list)
        
        # Botões de ação
        btn_layout = QHBoxLayout()
        
        self.export_pdf_btn = AnimatedButton("Exportar PDF", self.export_to_pdf)
        self.export_html_btn = AnimatedButton("Exportar HTML", self.export_to_html)
        self.clear_results_btn = AnimatedButton("Limpar Resultados", self.clear_results)
        
        btn_layout.addWidget(self.export_pdf_btn)
        btn_layout.addWidget(self.export_html_btn)
        btn_layout.addWidget(self.clear_results_btn)
        
        layout.addLayout(btn_layout)
        
        self.content_stack.addWidget(self.results_page)
    
    def init_help_page(self):
        self.help_page = QWidget()
        layout = QVBoxLayout()
        self.help_page.setLayout(layout)
        
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
            <h1>Ajuda do Sentinela Primeiro</h1>
            <h2>Como usar:</h2>
            <ol>
                <li>Digite o domínio alvo no campo de texto</li>
                <li>Clique em 'Iniciar Scan'</li>
                <li>Aguarde a conclusão do scan</li>
                <li>Visualize os resultados na aba 'Resultados'</li>
                <li>Exporte os resultados em PDF ou HTML se necessário</li>
            </ol>
            
            <h2>Módulos disponíveis:</h2>
            <ul>
                <li><b>XSS:</b> Detecta vulnerabilidades Cross-Site Scripting</li>
                <li><b>Google Dork:</b> Busca informações sensíveis usando técnicas de Google Dorking</li>
                <li><b>Directory Traversal:</b> Identifica possíveis vulnerabilidades de travessia de diretório</li>
                <li><b>Command Injection:</b> Detecta possíveis pontos de injeção de comandos</li>
                <li><b>Sensitive Data:</b> Procura por dados sensíveis expostos</li>
                <li><b>Misconfiguration:</b> Verifica más configurações de segurança</li>
                <li><b>SFPS:</b> Escaneia subdomínios e portas abertas</li>
            </ul>
        """)
        
        layout.addWidget(help_text)
        
        back_btn = AnimatedButton("Voltar", lambda: self.content_stack.setCurrentWidget(self.home_page))
        layout.addWidget(back_btn)
        
        self.content_stack.addWidget(self.help_page)
    
    def init_about_page(self):
        self.about_page = QWidget()
        layout = QVBoxLayout()
        self.about_page.setLayout(layout)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        about_content = QWidget()
        about_layout = QVBoxLayout()
        about_content.setLayout(about_layout)
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
            <h1 style="text-align: center;">Sobre o Sentinela Primeiro</h1>
            
            <p><strong>Sentinela Primeiro (SP)</strong> é uma ferramenta automatizada para Bug Bounty 
            que combina eficiência e inteligência para identificar vulnerabilidades web.</p>
            
            <h2>Funcionalidades:</h2>
            <ul>
                <li>Detecção de vulnerabilidades XSS (Cross-site scripting)</li>
                <li>Identificação de exposição de dados sensíveis</li>
                <li>Verificação de más configurações de segurança</li>
                <li>Escaneamento de portas abertas e subdomínios</li>
                <li>Interface moderna e intuitiva</li>
                <li>Geração de relatórios em PDF e HTML</li>
            </ul>
            
            <h2>Sobre o Desenvolvedor:</h2>
            <p><strong>Nicolau Zeus</strong>, criador do Sentinela Primeiro, é um amante da segurança 
            da informação dedicado a criar ferramentas automatizadas para Bug Bounty e Pentest.</p>
            
            <p>Sua abordagem combina conhecimento técnico profundo com uma paixão por automação, 
            tornando processos complexos mais eficientes e acessíveis.</p>
            
            <p style="text-align: center; font-size: 18px;">
                <strong>Use esta ferramenta com ética e responsabilidade.</strong>
            </p>
        """)
        
        about_layout.addWidget(about_text)
        scroll.setWidget(about_content)
        layout.addWidget(scroll)
        
        back_btn = AnimatedButton("Voltar", lambda: self.content_stack.setCurrentWidget(self.home_page))
        layout.addWidget(back_btn)
        
        self.content_stack.addWidget(self.about_page)
    
    def change_theme(self, theme):
        self.current_theme = theme
        self.apply_theme()
    
    def apply_theme(self):
        # Cores para cada tema (background, text, accent)
        themes = {
            "Azul Escuro": ("#142850", "#FFFFFF", "#005c8f"),
            "Preto": ("#000000", "#FFFFFF", "#333333"),
            "Branco": ("#FFFFFF", "#000000", "#005c8f")
        }
        
        bg_color, text_color, accent_color = themes[self.current_theme]
        
        # Aplicar paleta de cores
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(bg_color))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(text_color))
        palette.setColor(QPalette.ColorRole.Button, QColor(accent_color))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(text_color))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(accent_color))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(text_color))
        self.setPalette(palette)
        
        # Estilo adicional para componentes
        self.setStyleSheet(f"""
            QLineEdit, QTextEdit, QListWidget {{
                background-color: {self.lighten_color(bg_color)};
                color: {text_color};
                border: 1px solid {accent_color};
                border-radius: 4px;
                padding: 5px;
            }}
            
            QComboBox {{
                background-color: {self.lighten_color(bg_color)};
                color: {text_color};
                border: 1px solid {accent_color};
                padding: 5px;
            }}
            
            QProgressBar {{
                border: 1px solid {accent_color};
                border-radius: 4px;
                text-align: center;
            }}
            
            QProgressBar::chunk {{
                background-color: {accent_color};
            }}
        """)
    
    def lighten_color(self, color, amount=20):
        """Clareia uma cor hexadecimal"""
        color = QColor(color)
        return color.lighter(100 + amount).name()
    
    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Erro", "Por favor, digite um domínio válido")
            return
        
        # Resetar estado
        self.vulnerabilities = []
        self.progress_bar.setValue(0)
        self.scan_log.clear()
        self.scan_log.append(f"Iniciando scan em: {domain}")
        
        # Desabilitar botão durante o scan
        self.start_scan_btn.setEnabled(False)
        
        # Criar e configurar thread de scan
        self.scan_thread = ScanThread(domain)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.found_vulnerability.connect(self.add_vulnerability)
        self.scan_thread.scan_completed.connect(self.scan_finished)
        self.scan_thread.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def add_vulnerability(self, vuln):
        self.vulnerabilities.append(vuln)
        self.scan_log.append(f"[{vuln['type']}] {vuln['severity']}: {vuln['details']}")
        
        # Atualizar lista de resultados
        self.vuln_list.addItem(f"{vuln['type']} - {vuln['severity']}: {vuln['details'][:50]}...")
    
    def scan_finished(self, success, message):
        self.start_scan_btn.setEnabled(True)
        self.scan_log.append(message)
        
        if success:
            QMessageBox.information(self, "Scan Concluído", message)
            self.content_stack.setCurrentWidget(self.results_page)
        else:
            QMessageBox.warning(self, "Erro no Scan", message)
    
    def export_to_pdf(self):
        if not self.vulnerabilities:
            QMessageBox.warning(self, "Erro", "Nenhuma vulnerabilidade para exportar")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Salvar Relatório PDF", 
            f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", 
            "PDF Files (*.pdf)"
        )
        
        if path:
            try:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=16)
                
                # Cabeçalho
                pdf.cell(0, 10, "Relatório de Vulnerabilidades - Sentinela Primeiro", ln=True, align='C')
                pdf.ln(10)
                
                # Metadados
                pdf.set_font("Arial", size=12)
                pdf.cell(0, 10, f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
                pdf.cell(0, 10, f"Domínio: {self.domain_input.text()}", ln=True)
                pdf.cell(0, 10, f"Total de vulnerabilidades: {len(self.vulnerabilities)}", ln=True)
                pdf.ln(10)
                
                # Vulnerabilidades
                pdf.set_font("Arial", size=14, style='B')
                pdf.cell(0, 10, "Vulnerabilidades Encontradas:", ln=True)
                pdf.set_font("Arial", size=12)
                
                for idx, vuln in enumerate(self.vulnerabilities, 1):
                    pdf.set_font("Arial", size=12, style='B')
                    pdf.cell(0, 8, f"{idx}. {vuln['type']} ({vuln['severity']})", ln=True)
                    pdf.set_font("Arial", size=10)
                    pdf.multi_cell(0, 6, vuln['details'])
                    pdf.ln(5)
                
                pdf.output(path)
                QMessageBox.information(self, "Sucesso", f"Relatório salvo em:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha ao gerar PDF:\n{str(e)}")
    
    def export_to_html(self):
        if not self.vulnerabilities:
            QMessageBox.warning(self, "Erro", "Nenhuma vulnerabilidade para exportar")
            return
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Salvar Relatório HTML", 
            f"relatorio_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", 
            "HTML Files (*.html)"
        )
        
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Relatório de Vulnerabilidades - Sentinela Primeiro</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
        h1, h2 {{ color: #005c8f; }}
        .header {{ border-bottom: 2px solid #005c8f; padding-bottom: 10px; margin-bottom: 20px; }}
        .vuln {{ margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 10px; }}
        .high {{ color: #d9534f; font-weight: bold; }}
        .medium {{ color: #f0ad4e; }}
        .low {{ color: #5cb85c; }}
        .info {{ color: #5bc0de; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Vulnerabilidades</h1>
        <p><strong>Sentinela Primeiro</strong> - Bug Hunter Tool</p>
        <p><strong>Data:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Domínio:</strong> {self.domain_input.text()}</p>
        <p><strong>Total de vulnerabilidades:</strong> {len(self.vulnerabilities)}</p>
    </div>
    
    <h2>Detalhes das Vulnerabilidades</h2>
""")
                    
                    for idx, vuln in enumerate(self.vulnerabilities, 1):
                        severity_class = vuln['severity'].lower().replace('á', 'a').replace('é', 'e')
                        f.write(f"""
    <div class="vuln">
        <h3 class="{severity_class}">{idx}. {vuln['type']} - <span class="{severity_class}">{vuln['severity']}</span></h3>
        <p>{vuln['details']}</p>
    </div>
""")
                    
                    f.write("""
</body>
</html>
""")
                
                QMessageBox.information(self, "Sucesso", f"Relatório salvo em:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha ao gerar HTML:\n{str(e)}")
    
    def clear_results(self):
        self.vuln_list.clear()
        self.vulnerabilities = []
        QMessageBox.information(self, "Limpeza", "Resultados limpos com sucesso")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Verificar dependências
    try:
        window = SentinelaPrimeiro()
        window.show()
        sys.exit(app.exec())
    except ImportError as e:
        QMessageBox.critical(None, "Erro de Dependência", 
            f"Faltam dependências necessárias:\n{str(e)}\n\n"
            "Por favor, instale com:\n"
            "pip install PyQt6 matplotlib fpdf2")
        sys.exit(1)
