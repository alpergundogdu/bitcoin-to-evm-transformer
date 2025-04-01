
import { keccak_256 } from '@noble/hashes/sha3';
import { base58, base58check } from '@scure/base';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';

// Function to convert a Bitcoin address to EVM address
export function bitcoinToEvmAddress(bitcoinAddress: string): string {
  try {
    // Get the script for the address
    const pkScript = getPkScriptFromAddress(bitcoinAddress);
    
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

// Function to get the pk script from a Bitcoin address
function getPkScriptFromAddress(address: string): Uint8Array {
  // Check address type
  if (address.startsWith('1')) {
    // P2PKH (legacy)
    const decoded = base58check(keccak_256).decode(address);
    const pubKeyHash = decoded.slice(1);
    return new Uint8Array([
      0x76, // OP_DUP
      0xa9, // OP_HASH160
      0x14, // 20 bytes
      ...pubKeyHash,
      0x88, // OP_EQUALVERIFY
      0xac  // OP_CHECKSIG
    ]);
  } else if (address.startsWith('3')) {
    // P2SH (legacy)
    const decoded = base58check(keccak_256).decode(address);
    const scriptHash = decoded.slice(1);
    return new Uint8Array([
      0xa9, // OP_HASH160
      0x14, // 20 bytes
      ...scriptHash,
      0x87  // OP_EQUAL
    ]);
  } else if (address.startsWith('bc1') || address.startsWith('tb1')) {
    // Segwit or Taproot
    try {
      const prefix = address.startsWith('bc1') ? 'bc' : 'tb';
      
      // Try bech32 (Segwit v0)
      try {
        // Use type assertion to help TypeScript understand this is a valid format
        // The bech32 library expects strings with a specific format
        const { words } = bech32.decode(address as any);
        const version = words[0];
        const data = bech32.fromWords(words.slice(1));
        
        if (version === 0) {
          if (data.length === 20) {
            // P2WPKH
            return new Uint8Array([
              0x00, // OP_0
              0x14, // 20 bytes
              ...data
            ]);
          } else if (data.length === 32) {
            // P2WSH
            return new Uint8Array([
              0x00, // OP_0
              0x20, // 32 bytes
              ...data
            ]);
          }
        }
      } catch (e) {
        // Not segwit v0, try bech32m (Segwit v1+)
      }
      
      // Try bech32m (Taproot, Segwit v1+)
      try {
        // Use type assertion to help TypeScript understand this is a valid format
        const { words } = bech32m.decode(address as any);
        const version = words[0];
        const data = bech32m.fromWords(words.slice(1));
        
        if (version === 1) {
          // P2TR (Taproot)
          return new Uint8Array([
            0x51, // OP_1
            0x20, // 32 bytes
            ...data
          ]);
        }
      } catch (e) {
        throw new Error('Unsupported segwit address');
      }
    } catch (e) {
      throw new Error('Invalid bech32/bech32m address');
    }
  }
  
  throw new Error('Unsupported address format');
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
    // Legacy address validation
    if (address.startsWith('1') || address.startsWith('3')) {
      const decoded = base58check(keccak_256).decode(address);
      // Check if it's P2PKH (version 0x00) or P2SH (version 0x05)
      return decoded[0] === 0x00 || decoded[0] === 0x05;
    }
    
    // Segwit and Taproot address validation
    if (address.startsWith('bc1') || address.startsWith('tb1')) {
      try {
        // Try bech32 (Segwit v0)
        bech32.decode(address as any);
        return true;
      } catch (e) {
        try {
          // Try bech32m (Taproot, Segwit v1+)
          bech32m.decode(address as any);
          return true;
        } catch (e) {
          return false;
        }
      }
    }
    
    return false;
  } catch {
    return false;
  }
}

