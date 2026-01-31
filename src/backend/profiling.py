
import time
import functools

def profile_performance(func):
    """
    Decorator to measure execution time of functions.
    Logs start and end time to console.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        print(f"[PERF] Iniciando {func.__name__}...")
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            duration = end_time - start_time
            print(f"[PERF] {func.__name__} concluído em {duration:.4f} segundos")
            
    return wrapper
