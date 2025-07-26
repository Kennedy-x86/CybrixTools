# CybrixTools Testing Documentation

## Automated Testing Scripts

This project includes comprehensive automated testing scripts to ensure all functionality works correctly.

### Test Scripts Overview

1. **`test_cybrixtools.py`** - Main comprehensive test suite
2. **`continuous_test.py`** - Continuous testing runner

### Running Tests

#### Single Test Run
```bash
# Using the virtual environment
/Users/kennedy/CybrixTools/.venv/bin/python test_cybrixtools.py

# Or using the continuous test script
./continuous_test.py --once
```

#### Continuous Testing
```bash
# Run tests every 30 seconds
./continuous_test.py --watch
```

### Test Coverage

The test suite covers:

#### Module Testing
- ✅ **Hash Generator** - MD5, SHA1, SHA256, SHA512 hash generation
- ✅ **Encryption/Decryption** - AES-GCM encryption with key derivation
- ✅ **Password Analyzer** - Password strength analysis and feedback
- ✅ **TOTP Generator** - Time-based one-time password generation
- ✅ **Port Scanner** - Network port scanning functionality
- ✅ **Phishing Detector** - Email phishing detection
- ✅ **Steganography Detector** - Hidden data detection in images

#### Integration Testing
- ✅ **GUI Application Structure** - All GUI methods and components
- ✅ **File Operations** - Loading and saving encrypted files
- ✅ **End-to-End Encryption** - Complete encrypt/decrypt workflow
- ✅ **Error Handling** - Wrong passwords, invalid inputs, edge cases

#### File Structure
- ✅ **Required Files** - All necessary project files exist
- ✅ **Module Imports** - All dependencies are properly importable

### Test Results

Current Status: **100% Pass Rate** (60/60 tests passing)

### Issues Fixed During Testing

1. **Hash Generator**: Added missing SHA512 hash algorithm
2. **Password Analyzer**: Added proper handling for empty passwords
3. **Port Scanner**: Improved invalid IP address handling
4. **GUI Integration**: Fixed indentation and method structure issues

### Running Individual Module Tests

You can test individual modules by importing them:

```python
# Test encryption module
from modules import encryptdecrypt
key = encryptdecrypt.derive_key("test")
encrypted = encryptdecrypt.encrypt_data(key, b"test data")
decrypted = encryptdecrypt.decrypt_data(key, encrypted)
assert decrypted == b"test data"
```

### Adding New Tests

To add new tests, modify `test_cybrixtools.py`:

1. Create a new test function (e.g., `test_new_feature()`)
2. Add test cases using `results.add_test(test_name, condition, error_msg)`
3. Call the function from `main()`

### Debugging Failed Tests

When tests fail:
1. Check the error message in the test output
2. Run the specific module in isolation
3. Use the Python REPL to debug step by step
4. Fix the issue and re-run tests

### Best Practices

- Run tests before committing code changes
- Add tests for new features
- Use descriptive test names
- Test both success and failure cases
- Include edge cases (empty inputs, invalid data, etc.)
