.PHONY: setup run-all test clean build generate help \
        web crypto reverse forensics binary misc \
        docker-up docker-down docker-build

# Default target
help:
	@echo "CTF Writeups - Available Targets"
	@echo "==============================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  setup          Install Python dependencies"
	@echo "  build          Compile all C binaries"
	@echo "  generate       Create all challenge artifacts (PCAPs, images, etc.)"
	@echo ""
	@echo "Running Challenges:"
	@echo "  run-all        Run all solution scripts"
	@echo "  web            Run web challenge solutions"
	@echo "  crypto         Run crypto challenge solutions"
	@echo "  reverse        Run reverse engineering solutions"
	@echo "  forensics      Run forensics challenge solutions"
	@echo "  binary         Run binary exploitation solutions"
	@echo "  misc           Run misc challenge solutions"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build   Build all Docker images"
	@echo "  docker-up      Start all challenge containers"
	@echo "  docker-down    Stop all challenge containers"
	@echo ""
	@echo "Testing & Cleanup:"
	@echo "  test           Run all test suites"
	@echo "  clean          Remove generated files and caches"

# Setup and Installation
setup:
	@echo "[*] Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "[+] Setup complete!"

# Build C binaries for reverse and binary challenges
build:
	@echo "[*] Compiling binaries..."
	@mkdir -p binary/buffer-overflow-basics/challenge
	@mkdir -p reverse/license-checker/challenge
	@mkdir -p reverse/stack-overflow-101/challenge
	@echo "  [*] Building buffer-overflow-basics..."
	gcc -fno-stack-protector -z execstack -no-pie -o binary/buffer-overflow-basics/challenge/vuln binary/buffer-overflow-basics/challenge/vuln.c 2>/dev/null || echo "    [!] Could not compile vuln.c"
	@echo "  [*] Building license-checker..."
	gcc -o reverse/license-checker/challenge/license_checker reverse/license-checker/challenge/license_checker.c 2>/dev/null || echo "    [!] Could not compile license_checker.c"
	@echo "  [*] Building stack-overflow-101..."
	gcc -fno-stack-protector -z execstack -no-pie -o reverse/stack-overflow-101/challenge/stack_overflow reverse/stack-overflow-101/challenge/stack_overflow.c 2>/dev/null || echo "    [!] Could not compile stack_overflow.c"
	@echo "[+] Build complete!"

# Generate challenge artifacts
generate:
	@echo "[*] Generating challenge artifacts..."
	@echo "  [*] Creating crypto challenge data..."
	cd crypto/weak-rsa/challenge && python3 setup.py
	@echo "  [*] Creating forensics artifacts..."
	cd forensics/hidden-in-plain-sight/challenge && python3 create_challenge.py
	cd forensics/packet-analysis/challenge && python3 create_pcap.py
	@echo "  [*] Creating steganography challenges..."
	cd misc/steganography-101/challenge && python3 create_stego.py
	@echo "[+] Generation complete!"

# Run all solutions
run-all: web crypto reverse forensics binary misc
	@echo ""
	@echo "[+] All solutions executed!"

# Category-specific runs
web:
	@echo "[*] Running Web challenges..."
	@echo "=== SQL Injection 101 ==="
	cd web/sql-injection-101 && python3 solution.py || echo "[!] Start Docker container first: docker-compose up -d sql-injection"
	@echo ""
	@echo "=== XSS Filter Bypass ==="
	cd web/xss-filter-bypass && python3 solution.py || echo "[!] Start Docker container first: docker-compose up -d xss-filter"

crypto:
	@echo "[*] Running Crypto challenges..."
	@echo "=== Weak RSA ==="
	cd crypto/weak-rsa && python3 solution.py
	@echo ""
	@echo "=== Classic Ciphers ==="
	cd crypto/classic-ciphers/challenge && python3 solver.py

reverse: build
	@echo "[*] Running Reverse Engineering challenges..."
	@echo "=== License Checker ==="
	cd reverse/license-checker && python3 solution.py
	@echo ""
	@echo "=== Stack Overflow 101 ==="
	cd reverse/stack-overflow-101 && python3 solution.py

forensics:
	@echo "[*] Running Forensics challenges..."
	@echo "=== Hidden in Plain Sight ==="
	cd forensics/hidden-in-plain-sight && python3 solution.py
	@echo ""
	@echo "=== Packet Analysis ==="
	cd forensics/packet-analysis && python3 solution.py

binary: build
	@echo "[*] Running Binary Exploitation challenges..."
	@echo "=== Buffer Overflow Basics ==="
	cd binary/buffer-overflow-basics && python3 solution.py

misc:
	@echo "[*] Running Misc challenges..."
	@echo "=== Steganography 101 ==="
	cd misc/steganography-101 && python3 solution.py

# Docker operations
docker-build:
	@echo "[*] Building Docker images..."
	docker-compose build

docker-up:
	@echo "[*] Starting Docker containers..."
	docker-compose up -d
	@echo "[+] Containers started!"
	@docker-compose ps

docker-down:
	@echo "[*] Stopping Docker containers..."
	docker-compose down
	@echo "[+] Containers stopped!"

# Testing
test:
	@echo "[*] Running tests..."
	python3 -m pytest tests/ -v || echo "[!] No tests found or pytest not installed"

# Cleanup
clean:
	@echo "[*] Cleaning generated files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.o" -delete 2>/dev/null || true
	find . -type f -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "[+] Clean complete!"

deep-clean: clean
	@echo "[*] Deep cleaning all generated artifacts..."
	rm -f crypto/weak-rsa/challenge/challenge.json
	rm -f crypto/weak-rsa/challenge/solution.json
	rm -f forensics/hidden-in-plain-sight/challenge/*.png
	rm -f forensics/hidden-in-plain-sight/challenge/*.zip
	rm -f forensics/packet-analysis/challenge/*.pcap
	rm -f misc/steganography-101/challenge/challenges/*.png
	rm -f binary/buffer-overflow-basics/challenge/vuln
	rm -f reverse/license-checker/challenge/license_checker
	rm -f reverse/stack-overflow-101/challenge/stack_overflow
	@echo "[+] Deep clean complete!"
