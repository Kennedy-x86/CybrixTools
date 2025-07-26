#!/usr/bin/env python3
"""
Automated Test Script for CybrixTools
Tests all modules and functionality to ensure everything works correctly.
"""

import sys
import os
import traceback
import tempfile
import base64
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestResults:
    def __init__(self):
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.errors = []
    
    def add_test(self, test_name, passed, error_msg=None):
        self.total_tests += 1
        if passed:
            self.passed_tests += 1
            print(f"✓ {test_name}")
        else:
            self.failed_tests += 1
            self.errors.append(f"{test_name}: {error_msg}")
            print(f"✗ {test_name}: {error_msg}")
    
    def print_summary(self):
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Success Rate: {(self.passed_tests/self.total_tests)*100:.1f}%")
        
        if self.errors:
            print("\nFAILED TESTS:")
            for error in self.errors:
                print(f"  - {error}")

def test_imports(results):
    """Test all module imports"""
    print("\n--- Testing Module Imports ---")
    
    modules_to_test = [
        ('hash_generator', 'modules.hash_generator'),
        ('pwd_analyzer', 'modules.pwd_analyzer'),
        ('totp_generator', 'modules.totp_generator'),
        ('port_scanner', 'modules.port_scanner'),
        ('phishing_email_detector', 'modules.phishing_email_detector'),
        ('steganography_detector', 'modules.steganography_detector'),
        ('encryptdecrypt', 'modules.encryptdecrypt'),
    ]
    
    for module_name, import_path in modules_to_test:
        try:
            __import__(import_path)
            results.add_test(f"Import {module_name}", True)
        except Exception as e:
            results.add_test(f"Import {module_name}", False, str(e))
    
    # Test GUI imports
    try:
        import customtkinter as ctk
        results.add_test("Import customtkinter", True)
    except Exception as e:
        results.add_test("Import customtkinter", False, str(e))
    
    try:
        from PIL import Image, ImageTk
        results.add_test("Import PIL", True)
    except Exception as e:
        results.add_test("Import PIL", False, str(e))
    
    try:
        import qrcode
        results.add_test("Import qrcode", True)
    except Exception as e:
        results.add_test("Import qrcode", False, str(e))

def test_hash_generator(results):
    """Test hash generator functionality"""
    print("\n--- Testing Hash Generator ---")
    
    try:
        from modules import hash_generator
        
        # Test basic hash generation
        test_text = "Hello World"
        hashes = hash_generator.generate_hash(test_text)
        
        expected_algorithms = ['MD5', 'SHA1', 'SHA256', 'SHA512']
        for algo in expected_algorithms:
            if algo in hashes and hashes[algo]:
                results.add_test(f"Hash generation - {algo}", True)
            else:
                results.add_test(f"Hash generation - {algo}", False, "Hash not generated")
        
        # Test empty string
        empty_hashes = hash_generator.generate_hash("")
        results.add_test("Hash generation - empty string", len(empty_hashes) > 0)
        
    except Exception as e:
        results.add_test("Hash generator module", False, str(e))

def test_encryptdecrypt(results):
    """Test encryption/decryption functionality"""
    print("\n--- Testing Encryption/Decryption ---")
    
    try:
        from modules import encryptdecrypt
        
        # Test key derivation
        password = "test_password_123"
        key = encryptdecrypt.derive_key(password)
        results.add_test("Key derivation", len(key) == 32, f"Expected 32 bytes, got {len(key)}")
        
        # Test encryption/decryption round trip
        test_data = b"This is a test message for encryption!"
        encrypted = encryptdecrypt.encrypt_data(key, test_data)
        results.add_test("Data encryption", len(encrypted) > len(test_data))
        
        decrypted = encryptdecrypt.decrypt_data(key, encrypted)
        results.add_test("Data decryption", decrypted == test_data)
        
        # Test empty data
        empty_encrypted = encryptdecrypt.encrypt_data(key, b"")
        empty_decrypted = encryptdecrypt.decrypt_data(key, empty_encrypted)
        results.add_test("Empty data encryption/decryption", empty_decrypted == b"")
        
        # Test file operations
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            encryptdecrypt.save_encrypted(tmp_path, encrypted)
            loaded_data = encryptdecrypt.load_encrypted(tmp_path)
            results.add_test("File save/load operations", loaded_data == encrypted)
        finally:
            os.unlink(tmp_path)
        
        # Test wrong key (should fail)
        wrong_key = encryptdecrypt.derive_key("wrong_password")
        try:
            encryptdecrypt.decrypt_data(wrong_key, encrypted)
            results.add_test("Wrong key rejection", False, "Should have failed with wrong key")
        except Exception:
            results.add_test("Wrong key rejection", True)
        
    except Exception as e:
        results.add_test("Encryption/decryption module", False, str(e))

def test_password_analyzer(results):
    """Test password analyzer functionality"""
    print("\n--- Testing Password Analyzer ---")
    
    try:
        from modules import pwd_analyzer
        
        # Test weak password
        weak_score, weak_feedback = pwd_analyzer.check_password_strength("123")
        results.add_test("Weak password detection", weak_score <= 5)
        results.add_test("Weak password feedback", len(weak_feedback) > 0)
        
        # Test strong password
        strong_score, strong_feedback = pwd_analyzer.check_password_strength("MyStr0ng!P@ssw0rd2024")
        results.add_test("Strong password detection", strong_score >= 7)
        
        # Test empty password
        empty_score, empty_feedback = pwd_analyzer.check_password_strength("")
        results.add_test("Empty password handling", empty_score == 0)
        
    except Exception as e:
        results.add_test("Password analyzer module", False, str(e))

def test_totp_generator(results):
    """Test TOTP generator functionality"""
    print("\n--- Testing TOTP Generator ---")
    
    try:
        from modules import totp_generator
        
        # Generate a test secret
        secret = totp_generator.generate_secret()
        results.add_test("TOTP secret generation", len(secret) > 0)
        
        # Generate TOTP code
        code = totp_generator.get_totp_code(secret)
        results.add_test("TOTP code generation", len(code) == 6 and code.isdigit())
        
        # Test provisioning URI
        uri = totp_generator.get_provisioning_uri(secret)
        results.add_test("TOTP provisioning URI", uri.startswith("otpauth://totp/"))
        
    except Exception as e:
        results.add_test("TOTP generator module", False, str(e))

def test_port_scanner(results):
    """Test port scanner functionality"""
    print("\n--- Testing Port Scanner ---")
    
    try:
        from modules import port_scanner
        
        # Test scanning localhost (should be safe)
        # Test a port that's likely closed
        closed_result = port_scanner.scan_port("127.0.0.1", 9999)
        results.add_test("Port scanner - closed port", not closed_result)
        
        # Test invalid IP handling (should return False, not raise exception)
        invalid_result = port_scanner.scan_port("999.999.999.999", 80)
        results.add_test("Port scanner - invalid IP handling", not invalid_result)
        
    except Exception as e:
        results.add_test("Port scanner module", False, str(e))

def test_phishing_detector(results):
    """Test phishing email detector functionality"""
    print("\n--- Testing Phishing Detector ---")
    
    try:
        from modules import phishing_email_detector
        
        # Test with obviously suspicious content
        suspicious_email = """
        URGENT! Your account will be suspended!
        Click here immediately: http://fake-bank.com/login
        Verify your password now or lose access forever!
        """
        
        result = phishing_email_detector.check_email(suspicious_email)
        results.add_test("Phishing detection - suspicious email", 
                        isinstance(result, dict) and 'score' in result)
        results.add_test("Phishing detection - score range", 
                        0 <= result.get('score', -1) <= 100)
        
        # Test with normal content
        normal_email = "Hello, this is a normal email about work."
        normal_result = phishing_email_detector.check_email(normal_email)
        results.add_test("Phishing detection - normal email", 
                        normal_result.get('score', 100) < result.get('score', 0))
        
    except Exception as e:
        results.add_test("Phishing detector module", False, str(e))

def test_steganography_detector(results):
    """Test steganography detector functionality"""
    print("\n--- Testing Steganography Detector ---")
    
    try:
        from modules import steganography_detector
        
        # Create a simple test image
        try:
            from PIL import Image
            import numpy as np
            
            # Create a small test image
            test_image = Image.new('RGB', (100, 100), color='white')
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                tmp_path = tmp.name
                test_image.save(tmp_path)
            
            try:
                likelihood, findings = steganography_detector.check_upload(tmp_path)
                results.add_test("Steganography detection - basic functionality", 
                                isinstance(likelihood, (int, float)))
                results.add_test("Steganography detection - findings format", 
                                isinstance(findings, list))
            finally:
                os.unlink(tmp_path)
                
        except Exception as e:
            results.add_test("Steganography detector - image processing", False, str(e))
        
    except Exception as e:
        results.add_test("Steganography detector module", False, str(e))

def test_gui_app_structure(results):
    """Test GUI application structure without launching it"""
    print("\n--- Testing GUI Application Structure ---")
    
    try:
        from GUI.app_window import CybrixToolsApp
        
        # Test class exists and can be instantiated
        results.add_test("GUI app class import", True)
        
        # Test required methods exist
        required_methods = [
            'run_hash_generator',
            'run_encryptdecrypt',
            'run_password_analyzer',
            'run_totp_generator',
            'run_port_scanner',
            'run_phishing_detector',
            'run_steganography_detector',
            'encrypt_text',
            'decrypt_text',
            'load_file',
            'save_encrypted_file'
        ]
        
        for method_name in required_methods:
            has_method = hasattr(CybrixToolsApp, method_name)
            results.add_test(f"GUI method - {method_name}", has_method)
        
    except Exception as e:
        results.add_test("GUI application structure", False, str(e))

def test_integration_encrypt_decrypt_flow(results):
    """Test the complete encryption/decryption flow as used in GUI"""
    print("\n--- Testing Integration: Encrypt/Decrypt Flow ---")
    
    try:
        from modules import encryptdecrypt
        import base64
        
        # Simulate GUI workflow
        input_text = "This is a test message from the GUI!"
        password = "test_password"
        
        # Step 1: Encode input text (as GUI does)
        plaintext = input_text.encode()
        
        # Step 2: Derive key and encrypt
        key = encryptdecrypt.derive_key(password)
        ciphertext = encryptdecrypt.encrypt_data(key, plaintext)
        
        # Step 3: Base64 encode for display (as GUI does)
        cipher_b64 = base64.b64encode(ciphertext).decode()
        results.add_test("Integration - base64 encoding", len(cipher_b64) > 0)
        
        # Step 4: Decode from base64 and decrypt (as GUI does)
        decoded_ciphertext = base64.b64decode(cipher_b64)
        decrypted_plaintext = encryptdecrypt.decrypt_data(key, decoded_ciphertext)
        
        # Step 5: Decode to string (as GUI does)
        final_text = decrypted_plaintext.decode(errors="replace")
        
        results.add_test("Integration - complete encrypt/decrypt flow", 
                        final_text == input_text)
        
    except Exception as e:
        results.add_test("Integration encrypt/decrypt flow", False, str(e))

def test_file_structure(results):
    """Test that all required files exist"""
    print("\n--- Testing File Structure ---")
    
    required_files = [
        'main.py',
        'requirements.txt',
        'README.md',
        'GUI/app_window.py',
        'modules/hash_generator.py',
        'modules/pwd_analyzer.py',
        'modules/totp_generator.py',
        'modules/port_scanner.py',
        'modules/phishing_email_detector.py',
        'modules/steganography_detector.py',
        'modules/encryptdecrypt.py'
    ]
    
    for file_path in required_files:
        file_exists = Path(file_path).exists()
        results.add_test(f"File exists - {file_path}", file_exists)

def main():
    """Run all tests"""
    print("CybrixTools Automated Test Suite")
    print("="*60)
    
    results = TestResults()
    
    # Run all test suites
    test_file_structure(results)
    test_imports(results)
    test_hash_generator(results)
    test_encryptdecrypt(results)
    test_password_analyzer(results)
    test_totp_generator(results)
    test_port_scanner(results)
    test_phishing_detector(results)
    test_steganography_detector(results)
    test_gui_app_structure(results)
    test_integration_encrypt_decrypt_flow(results)
    
    # Print final results
    results.print_summary()
    
    # Return exit code based on results
    return 0 if results.failed_tests == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
