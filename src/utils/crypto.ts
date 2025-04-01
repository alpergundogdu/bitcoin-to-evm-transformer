
import { keccak_256 } from '@noble/hashes/sha3';
import { base58, base58check } from '@scure/base';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Function to convert a Bitcoin address to EVM address
export function bitcoinToEvmAddress(bitcoinAddress: string): string {
  try {
    // First, decode the Bitcoin address to get the public key hash
    const decoded = base58check.decode(bitcoinAddress);
    
    // The public key hash is the decoded data without the version byte
    const pubKeyHash = decoded.slice(1);
    
    // Create a P2PKH script: OP_DUP OP_HASH160 <len> <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    const pkScript = new Uint8Array([
      0x76, // OP_DUP
      0xa9, // OP_HASH160
      0x14, // 20 bytes
      ...pubKeyHash,
      0x88, // OP_EQUALVERIFY
      0xac  // OP_CHECKSIG
    ]);
    
    // Hash the script with keccak256
    const hashed = keccak_256(pkScript);
    
    // Take the last 20 bytes
    const evmAddressBytes = hashed.slice(hashed.length - 20);
    
    // Convert to a checksummed address
    return toChecksumAddress(bytesToHex(evmAddressBytes));
  } catch (error) {
    console.error('Error converting address:', error);
    throw new Error('Invalid Bitcoin address');
  }
}

// Function to convert an address to the checksummed EIP-55 format
function toChecksumAddress(address: string): string {
  address = address.toLowerCase().replace('0x', '');
  const hash = bytesToHex(keccak_256(address));
  let checksumAddress = '0x';
  
  for (let i = 0; i < address.length; i++) {
    // If the ith byte of the hash is >= 8, uppercase the ith character of the address
    if (parseInt(hash[i], 16) >= 8) {
      checksumAddress += address[i].toUpperCase();
    } else {
      checksumAddress += address[i];
    }
  }
  
  return checksumAddress;
}

// Validate Bitcoin address format
export function isValidBitcoinAddress(address: string): boolean {
  try {
    const decoded = base58check.decode(address);
    // Check if it's P2PKH (version 0x00) or P2SH (version 0x05)
    return decoded[0] === 0x00 || decoded[0] === 0x05;
  } catch {
    return false;
  }
}
