from v2ray_python.rpc import V2RayClient
import time

# Настройки API твоего Xray
API_HOST = '127.0.0.1'
API_PORT = 10085

client = V2RayClient(API_HOST, API_PORT)

def watch_uuid(email):
    print(f"[*] Мониторинг трафика для: {email}")
    last_val = 0
    
    try:
        while True:
            stats = client.get_user_stats(email)
            current_val = stats.downlink if stats else 0
            
            if current_val > last_val:
                print(f"[+] ТРАФИК ИДЕТ: {current_val} байт (Провайдер OK)")
            elif current_val == 0 and last_val == 0:
                print("[-] Трафика нет. Либо UUID неверный, либо провайдер блокирует.")
                
            last_val = current_val
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nСтоп мониторинг.")

if __name__ == "__main__":
    user_email = input("Введите email пользователя из конфига: ")
    watch_uuid(user_email)
