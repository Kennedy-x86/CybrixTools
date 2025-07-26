#!/usr/bin/env python3
"""
Simple Continuous Testing Script for CybrixTools
Runs tests periodically or on demand
"""

import os
import sys
import time
import subprocess
from pathlib import Path

def run_tests():
    """Run the test suite and return results"""
    print("🧪 Running tests...")
    try:
        # Get the Python executable for the virtual environment
        venv_python = "/Users/kennedy/CybrixTools/.venv/bin/python"
        test_script = Path(__file__).parent / "test_cybrixtools.py"
        
        result = subprocess.run(
            [venv_python, str(test_script)],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(test_script)
        )
        
        if result.returncode == 0:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed!")
            
        # Show summary line
        output_lines = result.stdout.split('\n')
        for line in output_lines:
            if 'Success Rate:' in line:
                print(f"📊 {line}")
                break
                
        return result.returncode == 0
        
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return False

def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '--once':
            # Run tests once and exit
            success = run_tests()
            sys.exit(0 if success else 1)
        elif sys.argv[1] == '--watch':
            # Simple polling mode
            print("🔄 CybrixTools Simple Continuous Testing")
            print("=" * 45)
            print("Running tests every 30 seconds...")
            print("Press Ctrl+C to stop")
            
            try:
                while True:
                    run_tests()
                    print(f"⏰ Next test run in 30 seconds...")
                    time.sleep(30)
            except KeyboardInterrupt:
                print("\n👋 Stopping continuous testing...")
                sys.exit(0)
    
    # Default: just run once
    success = run_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
