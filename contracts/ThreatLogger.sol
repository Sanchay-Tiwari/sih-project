// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatLogger {
    // 1. Define what a "Threat Record" looks like
    struct ThreatRecord {
        string ipAddress;
        uint256 threatScore;
        uint256 timestamp;
    }

    // 2. Create a list (array) to hold all the records permanently
    ThreatRecord[] public loggedThreats;

    // 3. Create an "Event" - this acts like a console.log that the frontend can listen to
    event ThreatLogged(string ipAddress, uint256 threatScore, uint256 timestamp);

    // 4. The main function your Node.js backend will call
    function logThreat(string memory _ipAddress, uint256 _threatScore) public {
        // block.timestamp is a built-in blockchain clock
        uint256 currentTime = block.timestamp;

        // Save the data to the blockchain array
        loggedThreats.push(ThreatRecord({
            ipAddress: _ipAddress,
            threatScore: _threatScore,
            timestamp: currentTime
        }));

        // Broadcast the event to the network
        emit ThreatLogged(_ipAddress, _threatScore, currentTime);
    }

    // 5. A helper function to count total threats logged
    function getTotalThreats() public view returns (uint256) {
        return loggedThreats.length;
    }
}