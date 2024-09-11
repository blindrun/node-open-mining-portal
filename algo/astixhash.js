const crypto = require('crypto');
const blake3 = require('blake3'); // External Blake3 library
const keccak = require('keccak'); // External Keccak library

// AstrixHash function using Blake3, Keccak, and SHA3
function astrixHash(input) {
    // Step 1: Convert input into a buffer
    let bufferInput = Buffer.isBuffer(input) ? input : Buffer.from(input, 'hex');

    // Step 2: Perform Blake3 hash
    let blakeHash = blake3.hash(bufferInput).toString('hex');

    // Step 3: Perform Keccak-256 hash
    let keccakHash = keccak('keccak256').update(blakeHash).digest('hex');

    // Step 4: Apply SHA3-256
    let sha3Hash = crypto.createHash('sha3-256').update(keccakHash, 'hex').digest('hex');

    return sha3Hash;
}

// Function to calculate the target based on difficulty
function calculateTarget(difficulty) {
    const maxTarget = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');
    return maxTarget / BigInt(difficulty);
}

// Function to check if a hash is valid against the difficulty target
function isHashValid(hash, target) {
    const hashBigInt = BigInt('0x' + hash.toString('hex'));
    return hashBigInt <= target;
}

// Function to serialize block header (simplified version)
function serializeBlockHeader(blockHeader) {
    const { version, prevHash, merkleRoot, timestamp, bits, nonce } = blockHeader;
    let header = Buffer.concat([
        Buffer.from(version.toString(16), 'hex'),
        Buffer.from(prevHash, 'hex'),
        Buffer.from(merkleRoot, 'hex'),
        Buffer.from(timestamp.toString(16), 'hex'),
        Buffer.from(bits.toString(16), 'hex'),
        Buffer.from(nonce.toString(16), 'hex'),
    ]);
    return header;
}

// Main mining function for AstrixHash, applying the above steps
function processBlock(blockHeader, difficulty) {
    const serializedHeader = serializeBlockHeader(blockHeader);
    const target = calculateTarget(difficulty);
    const blockHash = astrixHash(serializedHeader);
    const valid = isHashValid(blockHash, target);

    return {
        blockHash,
        isValid: valid,
    };
}

module.exports = {
    astrixHash,
    calculateTarget,
    isHashValid,
    processBlock,
};
