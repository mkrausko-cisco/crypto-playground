import time
import os
from concurrent import futures
from enum import Enum

from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class ConcurrencyMode(Enum):
    THREADS = 1
    PROCESSES = 2


# ==== CONFIGURATION ====
# Play with the values below.
N_OF_TASKS = 20
N_OF_WORKERS = None  # The `None` implies number of CPUs.

N_OF_ITERATIONS = 400_000

def hash_password(password, task_number):
    try:
        print(f'TASK[{task_number}]: started')
        algorithm = SHA512()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=algorithm,
            length=algorithm.digest_size,
            salt=salt,
            iterations=N_OF_ITERATIONS,
        )
        pw_hash = kdf.derive(password.encode())
        print(f'TASK[{task_number}]: done')
        return pw_hash
    except Exception as e:
        print(f'TASK[{task_number}]: error: {e}')
        raise e


def get_executor(mode):
    match mode:
        case ConcurrencyMode.THREADS:
            return futures.ThreadPoolExecutor(N_OF_WORKERS)
        case ConcurrencyMode.PROCESSES:
            return futures.ProcessPoolExecutor(N_OF_WORKERS)


def main(mode) -> float:
    start_time = time.time()
    with get_executor(mode) as executor:
        for i in range(N_OF_TASKS):
            executor.submit(hash_password, "my secret password", i)
    return time.time() - start_time



if __name__ == '__main__':
    print("SINGLE-THREAD SECTION")
    start_time = time.time()
    for i in range(N_OF_TASKS):
        hash_password("my secret password", i)
    elapsed_single = time.time() - start_time

    print('\n')
    print("THREADS SECTION")
    elapsed_threads = main(ConcurrencyMode.THREADS)

    print('\n')
    print("PROCESSES SECTION")
    elapsed_processes = main(ConcurrencyMode.PROCESSES)

    print('\n')
    print("MEASUREMENTS")
    print(f'sequence  : {elapsed_single:.6f} seconds')
    print(f'threads   : {elapsed_threads:.6f} seconds')
    print(f'processes : {elapsed_processes:.6f} seconds')
