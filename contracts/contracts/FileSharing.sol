// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stores public file references and wallet access decisions.
/// @dev Never store plaintext, filenames, passwords, or decryption keys on-chain.
contract FileSharing {
    struct FileRecord {
        uint256 fileId;
        string ipfsCid;
        string sha256Hash;
        address owner;
        uint256 uploadTime;
        bool exists;
    }

    uint256 public nextFileId = 1;
    mapping(uint256 => FileRecord) public files;
    mapping(uint256 => mapping(address => bool)) public fileAccess;
    mapping(uint256 => mapping(address => uint8)) public permissions;

    event FileUploaded(uint256 indexed fileId, string ipfsCid, string sha256Hash, address indexed owner);
    event FileUpdated(uint256 indexed fileId, string ipfsCid, string sha256Hash, address indexed editor);
    event AccessGranted(uint256 indexed fileId, address indexed targetUser, uint8 permissionLevel);
    event AccessRevoked(uint256 indexed fileId, address indexed targetUser);

    modifier onlyOwner(uint256 fileId) {
        require(files[fileId].exists, "File does not exist");
        require(files[fileId].owner == msg.sender, "Unauthorized: not the owner");
        _;
    }

    function uploadFile(string calldata ipfsCid, string calldata sha256Hash) external returns (uint256 fileId) {
        require(bytes(ipfsCid).length > 0, "Empty CID");
        require(bytes(sha256Hash).length == 64, "Expected SHA-256 hex");
        fileId = nextFileId++;
        files[fileId] = FileRecord(fileId, ipfsCid, sha256Hash, msg.sender, block.timestamp, true);
        fileAccess[fileId][msg.sender] = true;
        permissions[fileId][msg.sender] = 2;
        emit FileUploaded(fileId, ipfsCid, sha256Hash, msg.sender);
    }

    function grantAccess(uint256 fileId, address targetUser, uint8 permissionLevel) external onlyOwner(fileId) {
        require(targetUser != address(0), "Invalid target address");
        require(targetUser != msg.sender, "Owner already has access");
        require(permissionLevel == 1 || permissionLevel == 2, "Invalid permission");
        fileAccess[fileId][targetUser] = true;
        permissions[fileId][targetUser] = permissionLevel;
        emit AccessGranted(fileId, targetUser, permissionLevel);
    }

    function updateFile(uint256 fileId, string calldata ipfsCid, string calldata sha256Hash) external {
        require(files[fileId].exists, "File does not exist");
        require(fileAccess[fileId][msg.sender] && permissions[fileId][msg.sender] == 2, "Write access required");
        require(bytes(ipfsCid).length > 0, "Empty CID");
        require(bytes(sha256Hash).length == 64, "Expected SHA-256 hex");
        files[fileId].ipfsCid = ipfsCid;
        files[fileId].sha256Hash = sha256Hash;
        emit FileUpdated(fileId, ipfsCid, sha256Hash, msg.sender);
    }

    function revokeAccess(uint256 fileId, address targetUser) external onlyOwner(fileId) {
        require(targetUser != msg.sender, "Cannot revoke owner access");
        fileAccess[fileId][targetUser] = false;
        permissions[fileId][targetUser] = 0;
        emit AccessRevoked(fileId, targetUser);
    }

    function hasAccess(uint256 fileId, address user) external view returns (bool) {
        return files[fileId].exists && fileAccess[fileId][user];
    }
}

