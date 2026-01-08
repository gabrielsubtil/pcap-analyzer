import sqlite3
import threading

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(DatabaseManager, cls).__new__(cls)
                    cls._instance.conn = sqlite3.connect(':memory:', check_same_thread=False)
                    cls._instance.cursor = cls._instance.conn.cursor()
                    cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        """Inicializa as tabelas em memória."""
        self.cursor.executescript('''
            CREATE TABLE IF NOT EXISTS threats_strings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT,
                threat_desc TEXT,
                threat_explanation TEXT,
                payload TEXT,
                count INTEGER
            );
            
            CREATE INDEX IF NOT EXISTS idx_threat_type ON threats_strings(threat_type);

            DROP TABLE IF EXISTS dns_records;
            CREATE TABLE dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT,
                query_name TEXT,
                query_type TEXT,
                count INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_query_name ON dns_records(query_name);
        ''')
        self.conn.commit()

    def clear_data(self):
        """Limpa todos os dados para uma nova análise."""
        self.cursor.execute("DELETE FROM threats_strings")
        self.cursor.execute("DELETE FROM dns_records")
        self.conn.commit()

    def insert_strings_bulk(self, strings_list):
        """Insere lista de strings detectadas.
           strings_list: lista de dicionários {'type', 'desc', 'severity', 'payload', 'count'}
        """
        if not strings_list:
            return

        data = [
            (s['threatType'], s['threatDesc'], s.get('threatExplanation', ''), s['payload'], s.get('count', 1))
            for s in strings_list
        ]
        
        self.cursor.executemany('''
            INSERT INTO threats_strings (threat_type, threat_desc, threat_explanation, payload, count)
            VALUES (?, ?, ?, ?, ?)
        ''', data)
        self.conn.commit()

    def insert_dns_bulk(self, dns_list):
        """Insere lista de registros DNS.
           dns_list: lista de dicionários {'transaction_id', 'query_name', 'query_type', 'count'}
        """
        if not dns_list:
            return

        data = [
            (d.get('transaction_id', ''), d['query_name'], d['query_type'], d['count'])
            for d in dns_list
        ]
        
        self.cursor.executemany('''
            INSERT INTO dns_records (transaction_id, query_name, query_type, count)
            VALUES (?, ?, ?, ?)
        ''', data)
        self.conn.commit()

    def get_strings(self, limit=100, offset=0, filter_type=None):
        """Retorna strings paginadas, opcionalmente filtradas por tipo."""
        if filter_type:
            query = "SELECT threat_type, threat_desc, threat_explanation, payload, count FROM threats_strings WHERE threat_type = ? ORDER BY count DESC LIMIT ? OFFSET ?"
            params = (filter_type, limit, offset)
        else:
            query = "SELECT threat_type, threat_desc, threat_explanation, payload, count FROM threats_strings ORDER BY count DESC LIMIT ? OFFSET ?"
            params = (limit, offset)
            
        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        
        return [
            {
                'threatType': r[0],
                'threatDesc': r[1],
                'threatExplanation': r[2],
                'payload': r[3],
                'count': r[4]
            }
            for r in rows
        ]

    def get_dns_records(self, limit=100, offset=0):
        """Retorna registros DNS paginados."""
        query = "SELECT transaction_id, query_name, query_type, count FROM dns_records ORDER BY count DESC LIMIT ? OFFSET ?"
        params = (limit, offset)
        
        self.cursor.execute(query, params)
        rows = self.cursor.fetchall()
        
        return [
            {
                'transactionId': r[0],
                'queryName': r[1],
                'queryType': r[2],
                'count': r[3]
            }
            for r in rows
        ]

    def get_string_types(self):
        """Retorna tipos únicos de ameaças para o filtro."""
        self.cursor.execute("SELECT DISTINCT threat_type FROM threats_strings")
        return [r[0] for r in self.cursor.fetchall()]

    def close(self):
        self.conn.close()

# Singleton global access
db = DatabaseManager()
