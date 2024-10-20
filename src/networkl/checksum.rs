// Compute the internet checksum.
//
// Based on the reference implementation shown in RFC1071.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0;
    let mut count = data.len();
    let mut i = 0;

    // Get the sum of all 16-bit words
    while count > 1 {
        sum += u32::from(data[i]) << 8 | u32::from(data[i + 1]);
        i += 2;
        count -= 2;
    }

    // Add left-over byte in the case of an odd number of bytes
    if count > 0 {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement of the sum
    !sum as u16
}

// Validate the checksum over the whole packet (inc. checksum).
// A correct checksum ensures that the sum of all 16-bit words plus the
// checksum equals 0xFFFF, and the one's complement is 0x0000.
pub fn verify_internet_checksum(data: &[u8]) -> bool {
    internet_checksum(data) == 0
}
