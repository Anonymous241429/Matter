# Matter

# Anonymous
This repository contains all the research output about vulnerabilities in Matter Protocol.

# Matter Standard Specification-Implementation gap Specification Version v1.5.1 (Chipcontroller.cpp v1.5.1)

# vulnerability Type

Unauthorized Commissioning of Device

## Affected Product

Matter Standard Specification-Implementation gap Specification Version v1.5.1
 
## Affected Vendor

Matter Project Chip V1.5.1 - Chipcontroller.cpp v1.5.1

## Affected Component

Matter Project Chip v1.5.1, ChipDeviceController.cpp (function name: void DeviceCommissioner :: PerformCommissioningStep (CommissioningStage stage )

## CVE Number

[CVE-2026-78806] ([https://www.cve.org/CVERecord?id=CVE-2026-78806])

## Summary

An issue in Matter Standard Specification-Implementation gap v1.5.1 Matter Project Chip V1.5.1 allows a local attacker to obtain sensitive information via the PerformCommissioningStep function in the ChipDeviceController.cpp component.

## Tested Versions

Matter Project Chip V1.5.1 - Chipcontroller.cpp v1.5.1 

## Attack Vector

Adjacent: Attacker must be present on the commissioning network

## Product URLs

[Website] ((https://csa-iot.org/developer-resource/specifications-download-request)

## CVSSv3 Score

TBA

## CWE

TBA


# Code Build

## Python detector — most reliable (case-body-scoped, comment-aware)
python3 detect_gap1195.py \
    --src /path/to/src/controller/CHIPDeviceController.cpp
## → GAP-1195 CONFIRMED at case kArmFailsafe

## Semgrep — corrected rules (no brace restriction, no not-regex)
semgrep --config static/semgrep_gap1195_final.yaml \
        --no-git-ignore \
        /path/to/src/controller/CHIPDeviceController.cpp
## → 4-6 findings depending on whether fix exists in file

## Full test suite
python3 detect_gap1195.py \
    --src /path/to/src/controller/CHIPDeviceController.cpp \
    --run-semgrep --run-pytest
