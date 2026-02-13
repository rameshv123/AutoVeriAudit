from __future__ import annotations
import re
from typing import List
from utils.helpers import ContractArtifact, Vulnerability

# Replace _mock_detect_vulnerabilities with a real adapter to your verification engine.
# Expected: return List[Vulnerability] with trace and location populated.

def _mock_detect_vulnerabilities(contract: ContractArtifact) -> List[Vulnerability]:
    src = contract.source
    vulns: List[Vulnerability] = []
    cid = contract.contract_id

    def add(vtype: str, function: str, location: str, description: str, trace: List[str]):
        vid = f"{cid}:{vtype}:{len(vulns)+1}"
        vulns.append(Vulnerability(
            vuln_id=vid,
            contract_id=cid,
            vtype=vtype,
            function=function,
            location=location,
            description=description,
            trace=trace,
            features={}
        ))

    if re.search(r"\.call\{value:", src) and re.search(r"balances\[msg\.sender\]\s*-=", src):
        add(
            vtype="reentrancy",
            function="withdraw",
            location="withdraw(): external call before state update",
            description="Potential reentrancy: external call occurs prior to balance decrement.",
            trace=["enter withdraw()", "check balance", "external call to msg.sender", "state update balances[msg.sender] -= amount"]
        )

    if re.search(r"balances\[.*\]\s*\+=\s*msg\.value", src):
        add(
            vtype="arithmetic_overflow",
            function="deposit",
            location="deposit(): balances[msg.sender] += msg.value",
            description="Arithmetic update detected; ensure overflow-safe arithmetic for target compiler version.",
            trace=["enter deposit()", "state update balances[msg.sender] += msg.value"]
        )

    if re.search(r"function\s+adminSet\b", src) and not re.search(r"onlyOwner|onlyRole|require\(msg\.sender\s*==\s*owner", src):
        add(
            vtype="access_control",
            function="adminSet",
            location="adminSet(): missing access check",
            description="Missing access control on privileged state update function.",
            trace=["enter adminSet()", "no access check", "state update balances[user] = amount"]
        )

    if not vulns:
        add(
            vtype="info",
            function="N/A",
            location="N/A",
            description="No findings from mock detector. Connect the real verification engine for accurate results.",
            trace=["analysis completed"]
        )

    return vulns

def run_verification(contract: ContractArtifact) -> List[Vulnerability]:
    return _mock_detect_vulnerabilities(contract)
