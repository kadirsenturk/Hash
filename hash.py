import os
import random
import time

def generate_salt():
    """Rastgele bir tuz (salt) değeri üretir."""
    return random.randint(1, 1000)  # 1-1000 arası rastgele bir sayı

def get_timestamp(file_path):
    """Dosyanın son değiştirilme zaman damgasını döndürür."""
    return int(os.path.getmtime(file_path))  # Saniye cinsinden zaman damgası

def custom_hash(file_path, salt=None):
    """Dosyadan özgün bir hash değeri üretir (tuz ve zaman damgası ile)."""
    if not os.path.exists(file_path):
        return None, None, "Dosya bulunamadı!"

    # Eğer tuz verilmediyse, yeni bir tuz üret
    if salt is None:
        salt = generate_salt()

    try:
        # Dosyayı oku
        with open(file_path, "rb") as f:
            content = f.read()

        # Zaman damgasını al
        timestamp = get_timestamp(file_path)

        # Hash hesaplama: bayt toplamı + dosya boyutu + tuz + zaman damgası
        hash_value = sum(content)  # Baytların toplamı
        hash_value += os.path.getsize(file_path)  # Dosya boyutu
        hash_value += salt  # Tuz ekle
        hash_value += timestamp  # Zaman damgasını ekle
        hash_value = hash_value % 65536  # 16-bit bir değer için mod

        # Hex formatına çevir
        return hex(hash_value)[2:].zfill(4), salt, timestamp  # Hash, tuz ve zaman damgasını döndür
    except Exception as e:
        return None, None, f"Hata: {str(e)}"

def save_hash(file_path, hash_value, salt, timestamp):
    """Hash, tuz ve zaman damgası değerlerini bir dosyaya kaydeder."""
    with open("integrity_check.txt", "a") as f:
        f.write(f"{file_path} | Hash: {hash_value} | Salt: {salt} | Timestamp: {timestamp}\n")

def check_integrity(file_path, original_hash, salt, timestamp):
    """Dosyanın bütünlüğünü kontrol eder."""
    current_hash, _, error_or_timestamp = custom_hash(file_path, salt)
    if current_hash is None:
        return False, error_or_timestamp  # Hata mesajını döndür
    return current_hash == original_hash, "Kontrol tamamlandı."

def main():
    print("Dosya Bütünlük Kontrol Aracı (Kali Linux Uyumlu)")
    while True:
        print("\n1. Yeni bir dosyanın hash'ini üret")
        print("2. Dosya bütünlüğünü kontrol et")
        print("3. Çıkış")
        choice = input("Seçiminiz (1-3): ")

        if choice == "1":
            file_path = input("Dosya yolunu girin (örneğin: kali-linux-2023.1-installer-amd64.iso): ")
            hash_value, salt, timestamp_or_error = custom_hash(file_path)
            if hash_value:
                print(f"Hash: {hash_value} | Kullanılan Salt: {salt} | Timestamp: {timestamp_or_error}")
                save_hash(file_path, hash_value, salt, timestamp_or_error)
                print("Hash değeri 'integrity_check.txt' dosyasına kaydedildi.")
            else:
                print(f"Hata: {timestamp_or_error}")

        elif choice == "2":
            file_path = input("Kontrol edilecek dosya yolunu girin: ")
            original_hash = input("Orijinal hash değerini girin: ")
            salt = int(input("Kullanılan salt değerini girin: "))
            timestamp = int(input("Orijinal zaman damgasını girin: "))
            is_intact, message = check_integrity(file_path, original_hash, salt, timestamp)
            if is_intact:
                print("Dosya değişmemiş!")
            else:
                print(f"Dosya değiştirilmiş veya hata: {message}")

        elif choice == "3":
            print("Çıkış yapılıyor...")
            break

        else:
            print("Geçersiz seçim, lütfen 1-3 arasında bir sayı girin.")

if __name__ == "__main__":
    main()