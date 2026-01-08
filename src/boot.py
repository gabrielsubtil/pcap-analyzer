# Entry Point e Bridge API
# Português do Brasil

import webview
import sys
import os
import json
import threading
import struct

# Adiciona o diretório atual ao path para imports funcionarem corretamente
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from backend.parser import parse_pcap, parse_pcapng
from backend.analyzer import analyze_packets
from backend.consts import get_threat_catalog
from backend.database import db

class Api:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window
    
    def get_catalog(self):
        """Retorna o catálogo de ameaças para o frontend."""
        return get_threat_catalog()

    def get_analysis_strings(self, limit=100, offset=0, filter_type=None):
        """Retorna strings paginadas do SQLite em memória."""
        return db.get_strings(limit, offset, filter_type)

    def get_dns_records(self, limit=100, offset=0):
        """Retorna registros DNS paginados do SQLite em memória."""
        return db.get_dns_records(limit, offset)

    def get_string_filter_types(self):
        """Retorna tipos de ameaça disponíveis para filtro."""
        return db.get_string_types()


    def pick_files(self):
        """Abre diálogo de seleção de arquivos nativo."""
        file_types = ('PCAP Files (*.pcap;*.pcapng)', 'All files (*.*)')
        try:
            result = self._window.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=True, file_types=file_types)
            return result
        except Exception as e:
            print(f"Erro ao abrir diálogo: {e}")
            return []

    def echo(self, content):
        print(f"Echo from JS: {content}")
        return f"Python recebeu: {content}"

    def analyze_files(self, file_paths):
        """
        Recebe lista de caminhos de arquivos, processa e retorna o relatório.
        Executado em thread separada pelo pywebview se chamado via JS async.
        """
        print(f"Iniciando análise de {len(file_paths)} arquivos...")
        all_packets = []
        global_id_counter = 0

        # Magic Numbers
        PCAP_MAGIC_MICRO_BE = 0xa1b2c3d4
        PCAP_MAGIC_MICRO_LE = 0xd4c3b2a1
        PCAP_MAGIC_NANO_BE = 0xa1b23c4d
        PCAP_MAGIC_NANO_LE = 0x4d3cb2a1
        PCAPNG_MAGIC = 0x0A0D0D0A



        try:
            for path in file_paths:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"Arquivo não encontrado: {path}")

                file_size = os.path.getsize(path)
                with open(path, 'rb') as f:
                    # Lê headers globais para tentar identificar formato
                    header = f.read(4)
                    f.seek(0)
                    file_data = f.read()
                    
                    # Magic Number check
                    # PCAP LE: d4 c3 b2 a1
                    # PCAP BE: a1 b2 c3 d4
                    # PCAPNG: 0a 0d 0d 0a
                    
                    packets = []
                    if header == b'\n\r\r\n': # PCAPNG
                        packets = parse_pcapng(file_data)
                    else:
                        packets = parse_pcap(file_data)
                        
                    all_packets.extend(packets)

            print(f"Total de pacotes lidos: {len(all_packets)}. Iniciando análise...")
            
            if not all_packets:
                 return {'error': 'Nenhum pacote válido encontrado ou arquivo vazio.'}

            report = analyze_packets(all_packets)
            print("Análise concluída.")
            return report

        except FileNotFoundError as e:
            return {'error': f"Erro de Arquivo: {str(e)}"}
        except PermissionError:
             return {'error': "Erro de Permissão: Sem acesso para ler o arquivo."}
        except Exception as e:
            import traceback
            traceback_str = traceback.format_exc()
            print(traceback_str)
            
            error_type = type(e).__name__
            error_msg = str(e)
            
            # Melhorar msg para StopIteration (que geralmente é vazia)
            if not error_msg and isinstance(e, StopIteration):
                error_msg = "Item não encontrado (StopIteration) - provável regra ausente no consts.py"
            
            if "bytes pattern on a string-like object" in error_msg:
                friendly_msg = "Erro Conflito de Tipos (Bytes vs String)"
            else:
                friendly_msg = f"{error_type}: {error_msg}"
            
            # Retorna erro formatado com detalhes
            return {'error': f"Erro na Análise: {friendly_msg}\n\nDetalhes:\n{traceback_str}"}

    def minimize(self):
        if self._window:
            self._window.minimize()

    def close(self):
        if self._window:
            self._window.destroy()

def main():
    api = Api()
    
    # Caminho absoluto para o frontend
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller OneFile temp dir
        frontend_dir = os.path.join(sys._MEIPASS, 'frontend')
    else:
        # Development mode
        frontend_dir = os.path.join(current_dir, 'frontend')
    
    index_path = os.path.join(frontend_dir, 'index.html')
    
    if not os.path.exists(index_path):
        # Fallback manual
        index_path = os.path.join(os.getcwd(), 'src', 'frontend', 'index.html')

    # Caminho absoluto para assets
    if hasattr(sys, '_MEIPASS'):
         assets_dir = os.path.join(sys._MEIPASS, 'assets')
    else:
         assets_dir = os.path.join(current_dir, 'assets')
    
    icon_path = os.path.join(assets_dir, 'app.ico')

    window = webview.create_window(
        'PCAP Analyzer v5.0',
        url=index_path,
        js_api=api,
        width=1200,
        height=800,
        resizable=True,
        frameless=False,
        min_size=(800, 600),
        text_select=False
    )
    
    api.set_window(window)
    
    # Inicia o loop da interface gráfica
    # debug=False remove o menu de contexto nativo (Inspect, etc)
    webview.start(debug=False, http_server=True, icon=icon_path if os.path.exists(icon_path) else None)

if __name__ == '__main__':
    main()
