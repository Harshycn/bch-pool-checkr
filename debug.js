// Debug script to trace byte layout of Harshy Pool coinbase
const cb1 = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5603ce540e2f486172736879277320506f6f6cf09f8eb6e683b3e6acb2e4ba88e998aee587bae5a496e79a84e4babaf09f8f8defb88fe9a39ee59091e4b880e4b8aae7b981e58d8ee4b896e7958cf09f9a86f09f8c8f2fffffffff020000000000000000166a14';
const cb2 = '47d39d495e59f4a45c8ea112000000001976a91424518d67a6c4dba63bb4c21178ccb1a66f9b3f2988ac00000000';

const full = cb1 + cb2;
const bytes = Buffer.from(full, 'hex');

console.log('cb1 bytes:', cb1.length / 2);
console.log('cb2 bytes:', cb2.length / 2);
console.log('full bytes:', bytes.length);
console.log('scriptSigLen at offset 41:', bytes[41], '(decimal)');
console.log('scriptSig starts at offset 42');

// Find all instances of ffffffff in full
for (let i = 42; i < bytes.length - 4; i++) {
    if (bytes[i] === 0xff && bytes[i + 1] === 0xff && bytes[i + 2] === 0xff && bytes[i + 3] === 0xff) {
        console.log('ffffffff at offset', i, '-> next byte:', bytes[i + 4]?.toString(16));
    }
}

// The scriptSig is 86 bytes (0x56), starting at offset 42, so it ends at 42+86=128
// But we only have 83 bytes of scriptSig in cb1 (before ffffffff at offset 125)
const ssInCb1 = 125 - 42; // = 83
console.log('scriptSig bytes in cb1:', ssInCb1, '(expected 86, missing', 86 - ssInCb1, 'extranonce bytes)');

// After scriptSig+sequence, we have output_count at offset 129
// ffffffff at 125, so output area starts at 129
console.log('byte at 129 (output count):', bytes[129]?.toString(16));

// Try parsing outputs starting from output_count at 129
let pos = 130; // after output_count byte (02)
console.log('\nOutput 1:');
console.log('  value (8 bytes):', Buffer.from(bytes.slice(pos, pos + 8)).toString('hex'), '=', bytes.readBigUInt64LE(pos).toString());
pos += 8;
console.log('  script_len:', bytes[pos]);
const sl1 = bytes[pos]; pos++;
console.log('  script:', Buffer.from(bytes.slice(pos, pos + sl1)).toString('hex'));
pos += sl1;

console.log('\nOutput 2:');
console.log('  pos now:', pos, '/ total:', bytes.length);
if (pos + 8 <= bytes.length) {
    console.log('  value (8 bytes):', Buffer.from(bytes.slice(pos, pos + 8)).toString('hex'));
    pos += 8;
    if (pos < bytes.length) {
        console.log('  script_len:', bytes[pos]);
        const sl2 = bytes[pos]; pos++;
        console.log('  script:', Buffer.from(bytes.slice(pos, pos + sl2)).toString('hex'));
        pos += sl2;
    }
}

console.log('\nRemaining bytes after outputs:', bytes.length - pos, '(should be 4 for locktime)');
console.log('Remaining data:', Buffer.from(bytes.slice(pos)).toString('hex'));
