import asyncio
import os
import hashlib
from collections import defaultdict
import numpy as np
from typing import Dict, List, Tuple, Set
from client import CryptoClient, CryptoConfig
import secrets
from math import gcd

class CryptoAnalyzer:
    def __init__(self):
        self.known_plaintexts: Dict[bytes, bytes] = {}
        self.observed_ciphertexts: List[bytes] = []
        
    async def collect_samples(self, num_samples: int = 1000) -> None:
        """Собираем большее количество образцов шифротекстов для анализа"""
        config = CryptoConfig(
            server_url="http://localhost:8000",
            secret_key=b"super_secret_key_for_hmac",
            array_size=256,
            hash_size=32  # Обновленный размер хеша
        )
        
        async with CryptoClient(config) as client:
            await client.authenticate()
            
            # Собираем образцы с известным открытым текстом разной длины
            for i in range(num_samples):
                length = secrets.randbelow(1024) + 64  # Случайная длина от 64 до 1087 байт
                plaintext = os.urandom(length)  # Используем случайные данные
                ciphertext = await client.encrypt_message(plaintext)
                self.known_plaintexts[plaintext] = ciphertext
                self.observed_ciphertexts.append(ciphertext)

    def analyze_structure(self) -> Dict:
        """Расширенный анализ структуры шифротекста"""
        results = {
            "hash_entropy": [],
            "salt_entropy": [],
            "payload_entropy": [],
            "block_patterns": defaultdict(int),
            "hash_uniqueness": set(),
            "salt_uniqueness": set(),
            "length_distribution": defaultdict(int),
            "block_size_effectiveness": {}
        }
        
        for ct in self.observed_ciphertexts:
            # Анализ компонентов
            hash_part = ct[:32]  # 32-байтовый хеш
            salt = ct[32:64]  # 32-байтовый salt
            payload = ct[64:]
            
            # Анализ энтропии
            results["hash_entropy"].append(self._calculate_entropy(hash_part))
            results["salt_entropy"].append(self._calculate_entropy(salt))
            results["payload_entropy"].append(self._calculate_entropy(payload))
            
            # Анализ уникальности
            results["hash_uniqueness"].add(hash_part)
            results["salt_uniqueness"].add(salt)
            
            # Анализ распределения длин
            results["length_distribution"][len(ct)] += 1
            
            # Анализ паттернов блоков
            for i in range(0, len(payload), 64):
                block = payload[i:i+64]
                if len(block) == 64:  # Только полные блоки
                    results["block_patterns"][block[:8].hex()] += 1
        
        # Статистический анализ
        results["statistics"] = {
            "avg_hash_entropy": np.mean(results["hash_entropy"]),
            "avg_salt_entropy": np.mean(results["salt_entropy"]),
            "avg_payload_entropy": np.mean(results["payload_entropy"]),
            "unique_hashes": len(results["hash_uniqueness"]),
            "unique_salts": len(results["salt_uniqueness"]),
            "total_samples": len(self.observed_ciphertexts)
        }
        
        return results

    def differential_analysis(self) -> Dict:
        """Расширенный дифференциальный анализ"""
        results = {
            "xor_patterns": defaultdict(int),
            "position_dependencies": defaultdict(float),
            "key_correlations": [],
            "block_correlations": [],
            "salt_correlations": []
        }
        
        # Анализ разницы между последовательными шифротекстами
        for i in range(len(self.observed_ciphertexts) - 1):
            ct1 = self.observed_ciphertexts[i]
            ct2 = self.observed_ciphertexts[i + 1]
            
            # Анализ корреляций salt
            salt1 = ct1[32:64]
            salt2 = ct2[32:64]
            results["salt_correlations"].append(
                self._calculate_correlation(salt1, salt2)
            )
            
            # Анализ payload
            payload1 = ct1[64:]
            payload2 = ct2[64:]
            
            min_len = min(len(payload1), len(payload2))
            if min_len >= 64:  # Анализируем только если есть хотя бы один полный блок
                # XOR анализ
                xor_result = bytes(a ^ b for a, b in zip(payload1[:min_len], payload2[:min_len]))
                for j in range(0, min_len, 64):
                    block = xor_result[j:j+64]
                    if len(block) == 64:
                        results["xor_patterns"][block[:8].hex()] += 1
                
                # Анализ корреляций блоков
                for j in range(0, min_len - 64, 64):
                    block1 = payload1[j:j+64]
                    block2 = payload1[j+64:j+128]
                    if len(block1) == 64 and len(block2) == 64:
                        results["block_correlations"].append(
                            self._calculate_correlation(block1, block2)
                        )

        # Анализ позиционных зависимостей в известных парах открытый текст/шифротекст
        for pt, ct in self.known_plaintexts.items():
            payload = ct[64:]
            for pos in range(min(len(pt), len(payload))):
                correlation = abs(pt[pos] - payload[pos]) / 256.0
                results["position_dependencies"][pos] = correlation
        
        # Статистика
        results["statistics"] = {
            "avg_salt_correlation": np.mean(results["salt_correlations"]) if results["salt_correlations"] else 0,
            "avg_block_correlation": np.mean(results["block_correlations"]) if results["block_correlations"] else 0,
            "max_position_correlation": max(results["position_dependencies"].values()) if results["position_dependencies"] else 0,
            "unique_xor_patterns": len(results["xor_patterns"])
        }
        
        return results

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Расчет энтропии Шеннона"""
        if not data:
            return 0.0
        
        counts = defaultdict(int)
        for byte in data:
            counts[byte] += 1
        
        entropy = 0
        for count in counts.values():
            prob = count / len(data)
            entropy -= prob * np.log2(prob)
            
        return entropy

    @staticmethod
    def _calculate_correlation(data1: bytes, data2: bytes) -> float:
        """Расчет корреляции между двумя наборами байт"""
        if not data1 or not data2:
            return 0.0
        
        min_len = min(len(data1), len(data2))
        if min_len == 0:
            return 0.0
            
        correlation = sum(abs(a - b) / 256.0 for a, b in zip(data1[:min_len], data2[:min_len])) / min_len
        return correlation

    def try_key_recovery(self) -> Dict:
        """Попытка восстановления ключа"""
        results = {
            "possible_key_bytes": defaultdict(set),
            "key_byte_frequency": defaultdict(lambda: defaultdict(int)),
            "key_length_candidates": set(),
            "possible_array_dimensions": set()
        }
        
        # Анализ возможных значений ключа для каждой позиции
        for pt, ct in self.known_plaintexts.items():
            payload = ct[64:]  # Пропускаем hash и salt
            for i, (p, c) in enumerate(zip(pt, payload)):
                pos = i % 256  # Предполагаем максимальный размер ключа 256
                
                # Перебираем возможные значения ключа
                for k in range(1, 256, 2):  # Только нечетные числа (взаимно простые с 256)
                    if gcd(k, 256) == 1:
                        if (k * p) % 256 == c:
                            results["possible_key_bytes"][pos].add(k)
                            results["key_byte_frequency"][pos][k] += 1
        
        # Анализ периодичности в шифротексте для определения размера массива
        for ct in self.observed_ciphertexts:
            payload = ct[64:]
            for i in range(64, min(256, len(payload))):
                if all(payload[j] == payload[j-i] for j in range(i, min(i+64, len(payload)))):
                    results["key_length_candidates"].add(i)
        
        # Анализ возможных размерностей массива
        for length in results["key_length_candidates"]:
            for dim in range(2, 9):  # Проверяем размерности от 2 до 8
                if length == dim * dim * dim:
                    results["possible_array_dimensions"].add(dim)
        
        return results

async def main():
    analyzer = CryptoAnalyzer()
    
    print("Collecting samples...")
    await analyzer.collect_samples(1000)  # Увеличиваем количество образцов
    
    print("\nAnalyzing structure...")
    structure = analyzer.analyze_structure()
    print(f"Average entropy scores:")
    print(f"- Hash entropy: {structure['statistics']['avg_hash_entropy']:.2f}")
    print(f"- Salt entropy: {structure['statistics']['avg_salt_entropy']:.2f}")
    print(f"- Payload entropy: {structure['statistics']['avg_payload_entropy']:.2f}")
    print(f"Unique hashes: {structure['statistics']['unique_hashes']}")
    print(f"Unique salts: {structure['statistics']['unique_salts']}")
    
    print("\nPerforming differential analysis...")
    diff = analyzer.differential_analysis()
    print(f"Statistics:")
    print(f"- Average salt correlation: {diff['statistics']['avg_salt_correlation']:.4f}")
    print(f"- Average block correlation: {diff['statistics']['avg_block_correlation']:.4f}")
    print(f"- Maximum position correlation: {diff['statistics']['max_position_correlation']:.4f}")
    print(f"- Unique XOR patterns: {diff['statistics']['unique_xor_patterns']}")
    
    print("\nAttempting key recovery...")
    key_analysis = analyzer.try_key_recovery()
    print(f"Possible array dimensions: {sorted(key_analysis['possible_array_dimensions'])}")
    print(f"Number of key length candidates: {len(key_analysis['key_length_candidates'])}")
    print(f"Average possible values per key byte: {sum(len(v) for v in key_analysis['possible_key_bytes'].values()) / len(key_analysis['possible_key_bytes']):.2f}")

if __name__ == "__main__":
    asyncio.run(main())