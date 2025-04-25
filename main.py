import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton,
    QProgressBar, QLineEdit, QScrollArea, QMessageBox
)
from PyQt6.QtGui import QPixmap, QPalette, QColor, QFont
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QSize

# Importações dos módulos de detecção de vulnerabilidade
from sentinela_primeiro.modules import (
    xss_tool,
    dork_tool,
    traversal_tool,
    command_injection,
    sensitive_data,
    misconfiguration
)

# [restante do código continua igual, com as melhorias acima aplicadas no método `start_scan`]



class AnimatedButton(QPushButton):
    def __init__(self, text, function):
        super().__init__(text)
        self.default_size = QSize(200, 60)
        self.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                padding: 15px;
                background-color: #005c8f;
                color: white;
                border: 2px solid #006fa6;
                border-radius: 12px;
                min-width: 200px;
                min-height: 60px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0077b3;
            }
            QPushButton:pressed {
                background-color: #004d73;
            }
        """)
        self.setMinimumSize(self.default_size)
        self.setMaximumSize(self.default_size)
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


class AutomatedTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinela Primeiro - Bug Hunter")
        self.setGeometry(100, 100, 1000, 700)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.home_widget = self.create_home()
        self.stack.addWidget(self.home_widget)

        self.help_widget = self.create_help()
        self.stack.addWidget(self.help_widget)

        self.about_widget = self.create_about()
        self.stack.addWidget(self.about_widget)

        self.scan_widget = self.create_scan()
        self.stack.addWidget(self.scan_widget)

        self.current_theme = "Azul Escuro"
        self.background_image_path = ""
        self.apply_theme()

    def create_home(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pixmap = QPixmap("logotipo.png")
        label_logo = QLabel()
        label_logo.setPixmap(pixmap)
        label_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label_logo)

        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Azul Escuro", "Preto", "Branco"])
        self.theme_selector.currentTextChanged.connect(self.change_theme)
        self.theme_selector.setStyleSheet(
            "font-size: 16px; padding: 10px; background-color: #333; color: white; border-radius: 8px;"
        )
        layout.addWidget(self.theme_selector)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(40)
        button_layout.addWidget(AnimatedButton("Iniciar", lambda: self.stack.setCurrentWidget(self.scan_widget)))
        button_layout.addWidget(AnimatedButton("Ajuda", lambda: self.stack.setCurrentWidget(self.help_widget)))
        button_layout.addWidget(AnimatedButton("Sobre", lambda: self.stack.setCurrentWidget(self.about_widget)))

        layout.addLayout(button_layout)
        widget.setLayout(layout)
        return widget

    def create_scan(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(QLabel("<h2>Iniciar Scan</h2>"))

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Digite o domínio ou subdomínio")
        self.domain_input.setStyleSheet(
            "padding: 10px; font-size: 16px; border-radius: 8px; border: 2px solid #005c8f;"
        )
        layout.addWidget(self.domain_input)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #005c8f;
                border-radius: 8px;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #0077b3;
            }
        """)
        layout.addWidget(self.progress_bar)

        start_scan_button = AnimatedButton("Começar Scan", self.start_scan)
        layout.addWidget(start_scan_button)

        back_button = AnimatedButton("Voltar", lambda: self.stack.setCurrentWidget(self.home_widget))
        layout.addWidget(back_button)

        widget.setLayout(layout)
        return widget

    def create_help(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(QLabel("<h3>Ajuda</h3><p>Insira aqui as instruções sobre a ferramenta.</p>"))

        back_button = AnimatedButton("Voltar", lambda: self.stack.setCurrentWidget(self.home_widget))
        layout.addWidget(back_button)

        widget.setLayout(layout)
        return widget

    def create_about(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("background-color: transparent; border: none;")

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        about_label = QLabel()
        about_label.setTextFormat(Qt.TextFormat.RichText)
        about_label.setWordWrap(True)
        about_label.setStyleSheet("font-size: 16px; padding: 20px; color: white;")
        about_label.setText("""
            <h2 style="text-align: center;">Sobre - Sentinela Primeiro</h2>
            <p><strong>Sentinela Primeiro</strong> é um caçador de bugs que não apenas enfrenta desafios, mas <strong>os domina com inteligência e inovação</strong>.</p>

            <p>Com apenas <strong>21 anos</strong>, ele se destaca como um verdadeiro estrategista no mundo da <strong>cibersegurança</strong>, desvendando vulnerabilidades e aprimorando defesas com precisão cirúrgica.</p>

            <p>Para ele, não basta apenas encontrar falhas. A eficiência é seu combustível, e a automação, sua maior aliada. Criar <strong>ferramentas automatizadas</strong> não é apenas um hábito — é uma arte. Uma forma de potencializar suas investigações e tornar cada caçada <strong>mais rápida, poderosa e implacável</strong>.</p>

            <p>Com determinação e engenhosidade, <strong>Sentinela Primeiro avança</strong>, sempre buscando aperfeiçoamento, desafiando os limites e pronto para transformar o impossível em mais uma conquista.</p>

            <p style="text-align: center; font-size: 18px;"><strong>🔥 Aqui não se trata apenas de encontrar falhas. Trata-se de ser o melhor! 🚀</strong></p>
        """)
        content_layout.addWidget(about_label)
        scroll_area.setWidget(content_widget)

        layout.addWidget(scroll_area)

        back_button = AnimatedButton("Voltar", lambda: self.stack.setCurrentWidget(self.home_widget))
        layout.addWidget(back_button)

        widget.setLayout(layout)
        return widget

    def change_theme(self, theme):
        self.current_theme = theme
        self.apply_theme()

    def set_background_image(self, image_path):
        if os.path.isfile(image_path):
            self.background_image_path = image_path
            self.apply_theme()

    def apply_theme(self):
        colors = {
            "Azul Escuro": ("#142850", "white"),
            "Preto": ("#000000", "white"),
            "Branco": ("#FFFFFF", "black"),
        }
        bg_color, text_color = colors[self.current_theme]

        palette = QPalette()
        if self.background_image_path:
            self.setStyleSheet(f"""
                QMainWindow {{
                    background-image: url("{self.background_image_path}");
                    background-repeat: no-repeat;
                    background-position: center;
                    background-size: cover;
                }}
            """)
        else:
            palette.setColor(QPalette.ColorRole.Window, QColor(bg_color))
            self.setPalette(palette)
            self.setStyleSheet("")

        self.theme_selector.setStyleSheet(f"color: {text_color}; font-size: 16px;")

    def start_scan(self):
        domain = self.domain_input.text()
        if not domain:
            return

        self.progress_bar.setValue(0)
        # Chamadas às funções dos módulos (exemplo: você vai ajustar a lógica de cada um depois)
        xss_tool.run_xss(domain)
        self.progress_bar.setValue(15)
        dork_tool.scan_dorks(domain)
        self.progress_bar.setValue(30)
        traversal_tool.scan_traversal(domain)
        self.progress_bar.setValue(45)
        command_injection.scan_command_injection(domain)
        self.progress_bar.setValue(60)
        sensitive_data.scan_sensitive_data(domain)
        self.progress_bar.setValue(80)
        misconfiguration.scan_misconfiguration(domain)
        self.progress_bar.setValue(100)

    def update_progress(self, value):
        self.progress_bar.setValue(value)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AutomatedTool()
    window.set_background_image("caminho/para/sua/imagem.jpg")  # Ajusta conforme teu projeto
    window.show()
    sys.exit(app.exec())
