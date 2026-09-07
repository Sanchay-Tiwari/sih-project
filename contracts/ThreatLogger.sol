// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatLogger {
    struct ThreatRecord {
        string caseId;
        string evidenceHash;
        uint256 threatScore;
        uint256 timestamp;
    }

    ThreatRecord[] public loggedThreats;

    event ThreatLogged(string caseId, string evidenceHash, uint256 threatScore, uint256 timestamp);

    function logThreat(string memory caseId, string memory evidenceHash, uint256 threatScore) public returns (bool) {
        uint256 currentTime = block.timestamp;

        loggedThreats.push(ThreatRecord({
            caseId: caseId,
            evidenceHash: evidenceHash,
            threatScore: threatScore,
            timestamp: currentTime
        }));

        emit ThreatLogged(caseId, evidenceHash, threatScore, currentTime);
        return true;
    }

    function getTotalThreats() public view returns (uint256) {
        return loggedThreats.length;
    }
}