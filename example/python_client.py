#!/usr/bin/env python3
"""
Fastls MITM代理 Python客户端示例
演示如何通过MITM代理发送请求
"""

import requests
import json
import urllib3

# 禁用SSL警告（因为使用MITM代理）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_mitm_proxy():
    """测试MITM代理"""
    
    # MITM代理地址（需要先启动mitm_proxy.exe）
    proxy_url = "http://127.0.0.1:8888"
    
    # 目标URL
    target_url = "https://tls.peet.ws/api/all"
    
    print("通过MITM代理访问目标URL...")
    print(f"代理地址: {proxy_url}")
    print(f"目标URL: {target_url}\n")
    
    try:
        # 通过代理发送请求
        # 注意：对于MITM代理，需要禁用SSL验证或使用正确的CA证书
        # 使用 Session 来确保代理配置正确
        session = requests.Session()
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        session.verify = False  # 禁用SSL验证（因为使用MITM证书）
        
        response = session.get(
            target_url,
            timeout=30,
            # cert=("./../mitm-ca-cert.pem", "./../mitm-ca-key.pem"),
            verify=False,
            headers={
                "X-Mitm-Browser": "firefox",
                "X-Mitm-Proxy": "http://127.0.0.1:10809"
            }
        )
        
        print(f"状态码: {response.status_code}")
        print(f"响应头: {dict(response.headers)}")
        print(f"响应体长度: {len(response.text)} bytes")
        
        # 尝试解析JSON响应
        try:
            data = response.json()
            print(f"\n响应内容（JSON）:")
            print(json.dumps(data, indent=2, ensure_ascii=False))
        except:
            print(f"\n响应内容（前500字符）:")
            print(response.text[:500])
            
    except requests.exceptions.ProxyError as e:
        print(f"代理连接错误: {e}")
        print("\n请确保MITM代理已启动:")
        print("  cd services/fastls-mitm")
        print("  ./mitm_proxy.exe -addr :8888 -browser chrome142")
    except Exception as e:
        print(f"请求失败: {e}")


def test_with_custom_fingerprint():
    """使用自定义指纹测试"""
    
    proxy_url = "http://127.0.0.1:8888"
    target_url = "https://tls.peet.ws/api/all"
    
    print("\n使用自定义JA3指纹通过MITM代理访问...")
    
    # 注意：MITM代理的指纹设置在启动时配置
    # 这里只是演示如何通过代理发送请求
    try:
        # 使用 Session 来确保代理配置正确
        session = requests.Session()
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }
        session.verify = False  # 禁用SSL验证（因为使用MITM证书）
        
        response = session.get(
            target_url,
            timeout=30
        )
        
        print(f"状态码: {response.status_code}")
        print(f"请求成功!\n")
        
    except Exception as e:
        print(f"请求失败: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Fastls MITM代理 Python客户端示例")
    print("=" * 60)
    print()
    
    # 测试1: 基本代理功能
    test_mitm_proxy()
    
    # 测试2: 自定义指纹（需要在启动代理时设置）
    # test_with_custom_fingerprint()
    
    print("\n" + "=" * 60)
    print("提示: 启动MITM代理时可以使用以下参数:")
    print("  -addr :8888          # 监听地址")
    print("  -browser chrome142   # 浏览器类型")
    print("  -ja3 <指纹>          # 自定义JA3指纹")
    print("  -ja4r <指纹>         # 自定义JA4R指纹")
    print("=" * 60)

