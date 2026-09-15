# Python detector — most reliable (case-body-scoped, comment-aware)
python3 detect_gap1195.py \
    --src /path/to/src/controller/CHIPDeviceController.cpp
# → GAP-1195 CONFIRMED at case kArmFailsafe

# Semgrep — corrected rules (no brace restriction, no not-regex)
semgrep --config static/semgrep_gap1195_final.yaml \
        --no-git-ignore \
        /path/to/src/controller/CHIPDeviceController.cpp
# → 4-6 findings depending on whether fix exists in file

# Full test suite
python3 detect_gap1195.py \
    --src /path/to/src/controller/CHIPDeviceController.cpp \
    --run-semgrep --run-pytest
