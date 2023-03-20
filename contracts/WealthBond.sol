// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// This is the ETH/ERC20 borrow contract for Wealth.
//
// For 2-of-3 multisig, to authorize a spend, two signtures must be provided by 2 of the 3 owners.
// To generate the message to be signed, provide the destination address and
// spend amount (in wei) to the generateMessageToSign method.
// The signatures must be provided as the (v, r, s) hex-encoded coordinates.
// The S coordinate must be 0x00 or 0x01 corresponding to 0x1b and 0x1c, respectively.
//
// WARNING: The generated message is only valid until the next spend is executed.
//          after that, a new message will need to be calculated.
//
//
// INFO: This contract is ERC20 compatible.
// This contract can both receive ETH and ERC20 tokens.
// Notice that NFT (ERC721/ERC1155) is not supported. But can be transferred out throught spendAny.


contract Bond {
    uint256 public constant MAX_OWNER_COUNT = 9;

    // The N addresses which control the funds in this contract. The
    // owners of M of these addresses will need to both sign a message
    // allowing the funds in this contract to be spent.
    mapping(address => bool) private isOwner;
    address[] private owners;
    uint256 private immutable required;

    // The contract nonce is not accessible to the contract so we
    // implement a nonce-like variable for replay protection.
    uint256 private spendNonce = 0;

    bytes4 private constant SELECTOR =
        bytes4(keccak256(bytes("transfer(address,uint256)")));

    // An event sent when funds are received.
    event Funded(address from, uint256 value);

    // An event sent when a spend is triggered to the given address.
    event Spent(address to, uint256 transfer);

    // An event sent when a spendERC20 is triggered to the given address.
    event SpentERC20(address erc20contract, address to, uint256 transfer);

    // An event sent when an spendAny is executed.
    event SpentAny(address to, uint256 transfer);

    modifier validRequirement(uint256 ownerCount, uint256 _required) {
        require(
            ownerCount <= MAX_OWNER_COUNT &&
                _required <= ownerCount &&
                _required >= 1
        );
        _;
    }

    /// @dev Contract constructor sets initial owners and required number of confirmations.
    /// @param _owners List of initial owners.
    /// @param _required Number of required confirmations.
    constructor(
        address[] memory _owners,
        uint256 _required
    ) validRequirement(_owners.length, _required) {
        for (uint256 i = 0; i < _owners.length; i++) {
            //onwer should be distinct, and non-zero
            if (isOwner[_owners[i]] || _owners[i] == address(0x0)) {
                revert();
            }
            isOwner[_owners[i]] = true;
        }
        owners = _owners;
        required = _required;
    }

    // The receive function for this contract.
    receive() external payable {
        if (msg.value > 0) {
            emit Funded(msg.sender, msg.value);
        }
    }

    // @dev Returns list of owners.
    // @return List of owner addresses.
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getSpendNonce() external view returns (uint256) {
        return spendNonce;
    }

    function getRequired() external view returns (uint256) {
        return required;
    }

    function _safeTransfer(address token, address to, uint256 value) private {
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(SELECTOR, to, value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "Deposit: TRANSFER_FAILED"
        );
    }

    // Generates the message to sign given the output destination address and amount.
    // includes this contract's address and a nonce for replay protection.
    // One option to independently verify: https://leventozturk.com/engineering/sha3/ and select keccak
    function generateMessageToSign(
        bytes4 selector,
        address erc20Contract,
        address destination,
        uint256 value
    ) private view returns (bytes32) {
        require(destination != address(this));
        //the sequence should match generateMultiSigV2 in JS
        bytes32 message = keccak256(
            abi.encodePacked(
                address(this),
                selector,
                erc20Contract,
                destination,
                value,
                spendNonce
            )
        );
        return message;
    }

    function _messageToRecover(
        bytes4 selector,
        address erc20Contract,
        address destination,
        uint256 value
    ) private view returns (bytes32) {
        bytes32 hashedUnsignedMessage = generateMessageToSign(
            selector,
            erc20Contract,
            destination,
            value
        );
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, hashedUnsignedMessage));
    }

    // Generates the message to sign given the output destination address and amount.
    // includes this contract's address and a nonce for replay protection.
    // One option to independently verify: https://leventozturk.com/engineering/sha3/ and select keccak
    function generateMessageToSignAny(
        bytes4 selector,
        address destination,
        uint256 value,
        bytes calldata data
    ) private view returns (bytes32) {
        require(destination != address(this));
        //the sequence should match generateMultiSigV2 in JS
        bytes32 message = keccak256(
            abi.encodePacked(
                address(this),
                selector,
                destination,
                data,
                value,
                spendNonce
            )
        );
        return message;
    }

    function _messageToRecoverAny(
        bytes4 selector,
        address destination,
        uint256 value,
        bytes calldata data
    ) private view returns (bytes32) {
        bytes32 hashedUnsignedMessage = generateMessageToSignAny(
            selector,
            destination,
            value,
            data
        );
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        return keccak256(abi.encodePacked(prefix, hashedUnsignedMessage));
    }

    /**
     * @param destination: the ether receiver address.
     * @param value: the ether value, in wei.
     * @param vs, rs, ss: the signatures
     */
    function spend(
        address destination,
        uint256 value,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external {
        require(destination != address(this), "Not allow sending to yourself");
        require(
            address(this).balance >= value && value > 0,
            "balance or spend value invalid"
        );
        require(
            _validSignature(
                this.spend.selector,
                address(0x0),
                destination,
                value,
                vs,
                rs,
                ss
            ),
            "invalid signatures"
        );
        spendNonce = spendNonce + 1;
        //transfer will throw if fails
        (bool success, ) = destination.call{value: value}("");
        require(success, "transfer fail");
        emit Spent(destination, value);
    }

    /**
     * @param erc20contract: the erc20 contract address.
     * @param destination: the token receiver address.
     * @param value: the token value, in token minimum unit.
     * @param vs, rs, ss: the signatures
     */
    function spendERC20(
        address destination,
        address erc20contract,
        uint256 value,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) external {
        require(destination != address(this), "Not allow sending to yourself");
        //transfer erc20 token
        require(value > 0, "Erc20 spend value invalid");
        require(
            _validSignature(
                this.spendERC20.selector,
                erc20contract,
                destination,
                value,
                vs,
                rs,
                ss
            ),
            "invalid signatures"
        );
        spendNonce = spendNonce + 1;
        // transfer tokens from this contract to the destination address
        _safeTransfer(erc20contract, destination, value);
        emit SpentERC20(erc20contract, destination, value);
    }

    //This is usually for some emergent recovery, for example, recovery of NTFs, etc.
    function spendAny(
        address destination,
        uint256 value,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss,
        bytes calldata data
    ) external {
        require(destination != address(this), "Not allow sending to yourself");
        require(
            _validSignatureAny(
                this.spendAny.selector,
                destination,
                value,
                data,
                vs,
                rs,
                ss
            ),
            "invalid signatures"
        );
        spendNonce = spendNonce + 1;
        //transfer tokens from this contract to the destination address
        (bool success, ) = destination.call{value: value}(data);
        require(success, "call fail");
        emit SpentAny(destination, value);
    }

    // Confirm that the signature triplets (v1, r1, s1) (v2, r2, s2) ...
    // authorize a spend of this contract's funds to the given destination address.
    function _validSignature(
        bytes4 selector,
        address erc20Contract,
        address destination,
        uint256 value,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) private view returns (bool) {
        require(vs.length == rs.length);
        require(rs.length == ss.length);
        require(vs.length <= owners.length);
        require(vs.length >= required);
        bytes32 message = _messageToRecover(
            selector,
            erc20Contract,
            destination,
            value
        );
        address[] memory addrs = new address[](vs.length);
        for (uint256 i = 0; i < vs.length; i++) {
            //recover the address associated with the public key from elliptic curve signature or return zero on error
            addrs[i] = ecrecover(message, vs[i] + 27, rs[i], ss[i]);
        }
        require(_distinctOwners(addrs));
        return true;
    }

    // Confirm that the signature triplets (v1, r1, s1) (v2, r2, s2) ...
    // authorize a spend of this contract's funds to the given destination address.
    function _validSignatureAny(
        bytes4 selector,
        address destination,
        uint256 value,
        bytes calldata data,
        uint8[] calldata vs,
        bytes32[] calldata rs,
        bytes32[] calldata ss
    ) private view returns (bool) {
        require(vs.length == rs.length);
        require(rs.length == ss.length);
        require(vs.length <= owners.length);
        require(vs.length >= required);
        bytes32 message = _messageToRecoverAny(
            selector,
            destination,
            value,
            data
        );
        address[] memory addrs = new address[](vs.length);
        for (uint256 i = 0; i < vs.length; i++) {
            //recover the address associated with the public key from elliptic curve signature or return zero on error
            addrs[i] = ecrecover(message, vs[i] + 27, rs[i], ss[i]);
        }
        require(_distinctOwners(addrs));
        return true;
    }

    // Confirm the addresses as distinct owners of this contract.
    function _distinctOwners(
        address[] memory addrs
    ) private view returns (bool) {
        if (addrs.length > owners.length) {
            return false;
        }
        for (uint256 i = 0; i < addrs.length; i++) {
            if (!isOwner[addrs[i]]) {
                return false;
            }
            //address should be distinct
            for (uint256 j = 0; j < i; j++) {
                if (addrs[i] == addrs[j]) {
                    return false;
                }
            }
        }
        return true;
    }
}
